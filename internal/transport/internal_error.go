package transport

import (
	"encoding/json"
	"net/http"
)

type InternalError struct {
	Message string `json:"message"`
}

func (i InternalError) WriteTo(w http.ResponseWriter) {
	data, _ := json.Marshal(i)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(data)
}

func writeInternalError(w http.ResponseWriter, reason string) {
	InternalError{
		reason,
	}.WriteTo(w)
}
