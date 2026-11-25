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
#include <stdlib.h>
#include <string.h>

typedef struct {
    GMainLoop *loop;
    char      *pdf_uri;   // file:// URI of the output PDF
    int        dark;      // apply the dark print override before printing
    char      *error;     // g_strdup'd message on failure, NULL on success
} PdfJob;

static void pdf_job_fail(PdfJob *job, const char *msg) {
    if (job->error == NULL && msg != NULL) {
        job->error = g_strdup(msg);
    }
}

static void pdf_job_quit(PdfJob *job) {
    if (g_main_loop_is_running(job->loop)) {
        g_main_loop_quit(job->loop);
    }
}

// "failed" is emitted before the terminal "finished"; record the error and let
// "finished" unref the operation and quit the loop.
static void on_print_failed(WebKitPrintOperation *op, GError *error, gpointer data) {
    pdf_job_fail((PdfJob *)data, error && error->message ? error->message : "print failed");
}

static void on_print_finished(WebKitPrintOperation *op, gpointer data) {
    g_object_unref(op);
    pdf_job_quit((PdfJob *)data);
}

static void start_print(WebKitWebView *view, PdfJob *job) {
    WebKitPrintOperation *op = webkit_print_operation_new(view);
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

static void on_js_done(GObject *src, GAsyncResult *res, gpointer data) {
    PdfJob *job = (PdfJob *)data;
    GError *err = NULL;
    JSCValue *v = webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(src), res, &err);
    if (err) {
        g_error_free(err); // print anyway; the light theme is still valid output
    }
    if (v) {
        g_object_unref(v);
    }
    start_print(WEBKIT_WEB_VIEW(src), job);
}

static void on_load_changed(WebKitWebView *view, WebKitLoadEvent ev, gpointer data) {
    PdfJob *job = (PdfJob *)data;
    if (ev != WEBKIT_LOAD_FINISHED) {
        return;
    }
    if (job->dark) {
        const char *js = "document.documentElement.dataset.pdfTheme = 'dark';";
        webkit_web_view_evaluate_javascript(view, js, -1, NULL, NULL, NULL, on_js_done, job);
    } else {
        start_print(view, job);
    }
}

static gboolean on_timeout(gpointer data) {
    PdfJob *job = (PdfJob *)data;
    pdf_job_fail(job, "timed out rendering report PDF");
    pdf_job_quit(job);
    return G_SOURCE_REMOVE;
}

// render_pdf loads html_path in an offscreen WebKitWebView and prints it to
// pdf_path. Returns NULL on success or a g_malloc'd message the caller frees.
// Must be called on the GTK main thread.
static char *render_pdf(const char *html_path, const char *pdf_path, int dark, unsigned int timeout_s) {
    GError *uerr = NULL;
    char *html_uri = g_filename_to_uri(html_path, NULL, &uerr);
    if (!html_uri) {
        char *msg = g_strdup(uerr && uerr->message ? uerr->message : "bad html path");
        if (uerr) g_error_free(uerr);
        return msg;
    }
    char *pdf_uri = g_filename_to_uri(pdf_path, NULL, &uerr);
    if (!pdf_uri) {
        char *msg = g_strdup(uerr && uerr->message ? uerr->message : "bad pdf path");
        if (uerr) g_error_free(uerr);
        g_free(html_uri);
        return msg;
    }

    PdfJob job;
    job.loop = g_main_loop_new(NULL, FALSE);
    job.pdf_uri = pdf_uri;
    job.dark = dark;
    job.error = NULL;

    WebKitWebView *view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    g_object_ref_sink(view); // take ownership of the floating widget ref
    g_signal_connect(view, "load-changed", G_CALLBACK(on_load_changed), &job);
    webkit_web_view_load_uri(view, html_uri);

    guint tid = g_timeout_add_seconds(timeout_s, on_timeout, &job);
    g_main_loop_run(job.loop);
    g_source_remove(tid);

    g_object_unref(view);
    g_main_loop_unref(job.loop);
    g_free(html_uri);
    g_free(pdf_uri);
    return job.error; // g_strdup'd or NULL
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
