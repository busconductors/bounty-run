// Package bridge is the boundary between application services and the desktop
// runtime. Services depend on the interfaces here and never import Wails.
package bridge

// Emitter delivers a payload to the frontend on a named channel.
type Emitter interface {
	Emit(channel string, payload any)
}
