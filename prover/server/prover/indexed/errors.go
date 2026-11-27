package indexed

import "errors"

// Failure carries a stable reason without including request values or upstream
// response text. Codes survive both synchronous and queued delivery.
type Failure struct {
	Code    string
	Message string
	cause   error
}

func (failure *Failure) Error() string { return failure.Message }

func (failure *Failure) Unwrap() error { return failure.cause }

func failure(code, message string) *Failure {
	return &Failure{Code: code, Message: message}
}

func causedFailure(code, message string, cause error) *Failure {
	return &Failure{Code: code, Message: message, cause: cause}
}

func notReady(code string) *Failure {
	return causedFailure(code, ErrIndexerNotReady.Error(), ErrIndexerNotReady)
}

// Preserve failures already classified by a lower layer; foreign library errors
// receive the operation's safe reason rather than exposing their text.
func classifyFailure(code, message string, cause error) error {
	var classified *Failure
	if errors.As(cause, &classified) {
		return cause
	}
	return causedFailure(code, message, cause)
}
