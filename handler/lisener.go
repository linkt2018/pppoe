package handler

type Event int

const (
	EventStart                        Event = 0
	EventStop                         Event = 1
	EventDiscoveryBroadcast           Event = 2
	EventDiscoverySessionConfirmation Event = 3
	EventSessionRequest               Event = 4
	EventSessionACK                   Event = 5
	EventSessionNak                   Event = 6
	EventSessionAuthRequest           Event = 7
	EventError                        Event = 8
)

type Listener func(e Event, args ...interface{})
