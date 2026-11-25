//go:build linux && cgo && !gtk3 && !android && !server && !purego

package services

// WebKitGTK 6.0 / GTK4 print-to-PDF. This matches the build constraints of the
// Wails Linux WebKit backend (linux_cgo.go), so it compiles whenever the app's
// real webview backend does and links the same libraries.
//
// The whole render runs on the GTK main thread via application.InvokeSyncWithError:
// loading a URI and printing are asynchronous (signals delivered on the main
// loop), so render_pdf drives a NESTED GMainLoop on the main thread until the
// print "finished"/"failed" signal fires or a timeout elapses, then returns a
// strdup'd error message (NULL on success). Running a nested loop on the main
// thread is how GTK itself runs modal operations; the already-running outer
// loop resumes once render_pdf returns.

/*
#cgo linux pkg-config: gtk4 webkitgtk-6.0

#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>

// PdfJob is heap-allocated and refcounted because its address is handed to
// signal handlers and to an async evaluate_javascript callback that can fire
// AFTER render_pdf returns (e.g. a timeout mid-load). render_pdf holds one ref
// for its own frame; the pending JS call holds another. The last unref frees
// it, so no callback ever touches a freed job.
typedef struct {
    int                    refs;
    GMainLoop             *loop;
    char                  *pdf_uri;       // file:// URI of the output PDF
    int                    dark;          // apply the dark print override first
    char                  *error;         // g_strdup'd message, NULL on success
    guint                  timeout_id;    // 0 once the source is gone/fired
    gboolean               done;          // loop has been asked to quit
    gboolean               print_started; // guards against printing twice
    WebKitWebView         *view;
    WebKitPrintOperation  *op;            // current op; unreffed in teardown
    GCancellable          *cancellable;   // cancels the pending JS call
} PdfJob;

static void pdf_job_free(PdfJob *job) {
    if (job->loop) g_main_loop_unref(job->loop);
    if (job->cancellable) g_object_unref(job->cancellable);
    g_free(job->pdf_uri);
    g_free(job->error); // normally NULL: render_pdf steals it before unref
    g_free(job);
}

static void pdf_job_unref(PdfJob *job) {
    if (--job->refs == 0) {
        pdf_job_free(job);
    }
}

// pdf_job_finish records the first error (NULL keeps a prior success/error) and
// quits the loop once. Every terminal path funnels through it.
static void pdf_job_finish(PdfJob *job, const char *msg) {
    if (job->error == NULL && msg != NULL) {
        job->error = g_strdup(msg);
    }
    job->done = TRUE;
    if (g_main_loop_is_running(job->loop)) {
        g_main_loop_quit(job->loop);
    }
}

// "failed" is emitted before the terminal "finished"; record the error and let
// "finished" quit the loop. The op itself is unreffed in render_pdf's teardown.
static void on_print_failed(WebKitPrintOperation *op, GError *error, gpointer data) {
    pdf_job_finish((PdfJob *)data, error && error->message ? error->message : "print failed");
}

static void on_print_finished(WebKitPrintOperation *op, gpointer data) {
    pdf_job_finish((PdfJob *)data, NULL);
}

static void start_print(WebKitWebView *view, PdfJob *job) {
    if (job->print_started || job->done) {
        return; // at most one print, never after a failure/timeout
    }
    job->print_started = TRUE;
    WebKitPrintOperation *op = webkit_print_operation_new(view);
    job->op = op; // kept so teardown can disconnect + unref it on any path
    GtkPrintSettings *settings = gtk_print_settings_new();
    // The GTK "Print to File" backend writes PDF to output-uri with no dialog.
    gtk_print_settings_set_printer(settings, "Print to File");
    gtk_print_settings_set(settings, GTK_PRINT_SETTINGS_OUTPUT_URI, job->pdf_uri);
    gtk_print_settings_set(settings, GTK_PRINT_SETTINGS_OUTPUT_FILE_FORMAT, "pdf");
    webkit_print_operation_set_print_settings(op, settings);
    g_object_unref(settings);
    g_signal_connect(op, "failed", G_CALLBACK(on_print_failed), job);
    g_signal_connect(op, "finished", G_CALLBACK(on_print_finished), job);
    webkit_print_operation_print(op);
}

// on_js_done runs after render_pdf may already have returned (hence the ref it
// holds and the done/cancelled guards).
static void on_js_done(GObject *src, GAsyncResult *res, gpointer data) {
    PdfJob *job = (PdfJob *)data;
    GError *err = NULL;
    JSCValue *v = webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(src), res, &err);
    if (v) {
        g_object_unref(v);
    }
    if (err) {
        g_error_free(err); // print anyway; the light theme is still valid output
    }
    if (!job->done) {
        start_print(WEBKIT_WEB_VIEW(src), job);
    }
    pdf_job_unref(job);
}

static void on_load_changed(WebKitWebView *view, WebKitLoadEvent ev, gpointer data) {
    PdfJob *job = (PdfJob *)data;
    if (ev != WEBKIT_LOAD_FINISHED || job->done || job->print_started) {
        return;
    }
    if (job->dark) {
        job->refs++; // on_js_done will unref
        const char *js = "document.documentElement.dataset.pdfTheme = 'dark';";
        webkit_web_view_evaluate_javascript(view, js, -1, NULL, NULL,
                                            job->cancellable, on_js_done, job);
    } else {
        start_print(view, job);
    }
}

// load-failed fires before any LOAD_FINISHED on error; record it so a later
// spurious LOAD_FINISHED cannot print the error page and report success.
static gboolean on_load_failed(WebKitWebView *view, WebKitLoadEvent ev,
                               const char *failing_uri, GError *error, gpointer data) {
    pdf_job_finish((PdfJob *)data, error && error->message ? error->message : "load failed");
    return TRUE; // stop default error-page handling
}

static void on_web_process_terminated(WebKitWebView *view,
                                      WebKitWebProcessTerminationReason reason, gpointer data) {
    pdf_job_finish((PdfJob *)data, "web process terminated");
}

static gboolean on_timeout(gpointer data) {
    PdfJob *job = (PdfJob *)data;
    job->timeout_id = 0; // the source removes itself; teardown must not re-remove
    pdf_job_finish(job, "timed out rendering report PDF");
    return G_SOURCE_REMOVE;
}

// render_pdf loads html_path in an offscreen WebKitWebView and prints it to
// pdf_path. Returns NULL on success or a g_strdup'd message the caller frees.
// Must be called on the GTK main thread.
static char *render_pdf(const char *html_path, const char *pdf_path, int dark, unsigned int timeout_s) {
    GError *uerr = NULL;
    char *html_uri = g_filename_to_uri(html_path, NULL, &uerr);
    if (!html_uri) {
        char *msg = g_strdup(uerr && uerr->message ? uerr->message : "bad html path");
        if (uerr) g_error_free(uerr);
        return msg;
    }

    PdfJob *job = g_new0(PdfJob, 1);
    job->refs = 1;
    job->loop = g_main_loop_new(NULL, FALSE);
    job->dark = dark;
    job->cancellable = g_cancellable_new();
    job->pdf_uri = g_filename_to_uri(pdf_path, NULL, &uerr);
    if (!job->pdf_uri) {
        char *msg = g_strdup(uerr && uerr->message ? uerr->message : "bad pdf path");
        if (uerr) g_error_free(uerr);
        g_free(html_uri);
        pdf_job_unref(job);
        return msg;
    }

    WebKitWebView *view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    g_object_ref_sink(view); // take ownership of the floating widget ref
    job->view = view;
    g_signal_connect(view, "load-changed", G_CALLBACK(on_load_changed), job);
    g_signal_connect(view, "load-failed", G_CALLBACK(on_load_failed), job);
    g_signal_connect(view, "web-process-terminated", G_CALLBACK(on_web_process_terminated), job);
    webkit_web_view_load_uri(view, html_uri);

    job->timeout_id = g_timeout_add_seconds(timeout_s, on_timeout, job);
    g_main_loop_run(job->loop);

    // Teardown on the main thread: no view/op signal can fire after this, and a
    // still-pending JS call is cancelled (it holds its own ref and unrefs late).
    if (job->timeout_id != 0) {
        g_source_remove(job->timeout_id);
    }
    g_signal_handlers_disconnect_by_data(view, job);
    if (job->op) {
        g_signal_handlers_disconnect_by_data(job->op, job);
        g_object_unref(job->op);
        job->op = NULL;
    }
    g_cancellable_cancel(job->cancellable);
    g_object_unref(view);
    g_free(html_uri);

    char *ret = job->error; // steal: pdf_job_free must not free what we return
    job->error = NULL;
    pdf_job_unref(job);
    return ret;
}
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// pdfRenderTimeoutSeconds bounds a single render so a stuck load or print can
// never hang the UI call indefinitely.
const pdfRenderTimeoutSeconds = 60

// webkitRenderPDF renders htmlPath to pdfPath via WebKitGTK, on the GTK main
// thread. theme == "dark" keeps the report's dark print treatment.
func webkitRenderPDF(htmlPath, pdfPath, theme string) error {
	return application.InvokeSyncWithError(func() error {
		cHTML := C.CString(htmlPath)
		cPDF := C.CString(pdfPath)
		defer C.free(unsafe.Pointer(cHTML))
		defer C.free(unsafe.Pointer(cPDF))
		dark := C.int(0)
		if theme == "dark" {
			dark = C.int(1)
		}
		msg := C.render_pdf(cHTML, cPDF, dark, C.uint(pdfRenderTimeoutSeconds))
		if msg != nil {
			err := errors.New("render report PDF: " + C.GoString(msg))
			C.g_free(C.gpointer(msg))
			return err
		}
		return nil
	})
}
