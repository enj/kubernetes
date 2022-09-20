//go:build tinygo.wasm

package main

import (
	json "encoding/json"

	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(in *jlexer.Lexer, out *AdmissionReview) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "request":
			if in.IsNull() {
				in.Skip()
				out.Request = nil
			} else {
				if out.Request == nil {
					out.Request = new(AdmissionRequest)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson1(in, out.Request)
			}
		case "response":
			if in.IsNull() {
				in.Skip()
				out.Response = nil
			} else {
				if out.Response == nil {
					out.Response = new(AdmissionResponse)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson2(in, out.Response)
			}
		case "kind":
			out.Kind = string(in.String())
		case "apiVersion":
			out.APIVersion = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(out *jwriter.Writer, in AdmissionReview) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Request != nil {
		const prefix string = ",\"request\":"
		first = false
		out.RawString(prefix[1:])
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson1(out, *in.Request)
	}
	if in.Response != nil {
		const prefix string = ",\"response\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson2(out, *in.Response)
	}
	if in.Kind != "" {
		const prefix string = ",\"kind\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Kind))
	}
	if in.APIVersion != "" {
		const prefix string = ",\"apiVersion\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.APIVersion))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v AdmissionReview) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v AdmissionReview) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *AdmissionReview) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *AdmissionReview) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson(l, v)
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson2(in *jlexer.Lexer, out *AdmissionResponse) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "uid":
			out.UID = UID(in.String())
		case "allowed":
			out.Allowed = bool(in.Bool())
		case "status":
			if in.IsNull() {
				in.Skip()
				out.Result = nil
			} else {
				if out.Result == nil {
					out.Result = new(Status)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson3(in, out.Result)
			}
		case "patch":
			if in.IsNull() {
				in.Skip()
				out.Patch = nil
			} else {
				out.Patch = in.Bytes()
			}
		case "patchType":
			if in.IsNull() {
				in.Skip()
				out.PatchType = nil
			} else {
				if out.PatchType == nil {
					out.PatchType = new(PatchType)
				}
				*out.PatchType = PatchType(in.String())
			}
		case "auditAnnotations":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.AuditAnnotations = make(map[string]string)
				} else {
					out.AuditAnnotations = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v2 string
					v2 = string(in.String())
					(out.AuditAnnotations)[key] = v2
					in.WantComma()
				}
				in.Delim('}')
			}
		case "warnings":
			if in.IsNull() {
				in.Skip()
				out.Warnings = nil
			} else {
				in.Delim('[')
				if out.Warnings == nil {
					if !in.IsDelim(']') {
						out.Warnings = make([]string, 0, 4)
					} else {
						out.Warnings = []string{}
					}
				} else {
					out.Warnings = (out.Warnings)[:0]
				}
				for !in.IsDelim(']') {
					var v3 string
					v3 = string(in.String())
					out.Warnings = append(out.Warnings, v3)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson2(out *jwriter.Writer, in AdmissionResponse) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"uid\":"
		out.RawString(prefix[1:])
		out.String(string(in.UID))
	}
	{
		const prefix string = ",\"allowed\":"
		out.RawString(prefix)
		out.Bool(bool(in.Allowed))
	}
	if in.Result != nil {
		const prefix string = ",\"status\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson3(out, *in.Result)
	}
	if len(in.Patch) != 0 {
		const prefix string = ",\"patch\":"
		out.RawString(prefix)
		out.Base64Bytes(in.Patch)
	}
	if in.PatchType != nil {
		const prefix string = ",\"patchType\":"
		out.RawString(prefix)
		out.String(string(*in.PatchType))
	}
	if len(in.AuditAnnotations) != 0 {
		const prefix string = ",\"auditAnnotations\":"
		out.RawString(prefix)
		{
			out.RawByte('{')
			v6First := true
			for v6Name, v6Value := range in.AuditAnnotations {
				if v6First {
					v6First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v6Name))
				out.RawByte(':')
				out.String(string(v6Value))
			}
			out.RawByte('}')
		}
	}
	if len(in.Warnings) != 0 {
		const prefix string = ",\"warnings\":"
		out.RawString(prefix)
		{
			out.RawByte('[')
			for v7, v8 := range in.Warnings {
				if v7 > 0 {
					out.RawByte(',')
				}
				out.String(string(v8))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson3(in *jlexer.Lexer, out *Status) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "metadata":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson4(in, &out.ListMeta)
		case "status":
			out.Status = string(in.String())
		case "message":
			out.Message = string(in.String())
		case "reason":
			out.Reason = StatusReason(in.String())
		case "details":
			if in.IsNull() {
				in.Skip()
				out.Details = nil
			} else {
				if out.Details == nil {
					out.Details = new(StatusDetails)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson5(in, out.Details)
			}
		case "code":
			out.Code = int32(in.Int32())
		case "kind":
			out.Kind = string(in.String())
		case "apiVersion":
			out.APIVersion = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson3(out *jwriter.Writer, in Status) {
	out.RawByte('{')
	first := true
	_ = first
	if true {
		const prefix string = ",\"metadata\":"
		first = false
		out.RawString(prefix[1:])
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson4(out, in.ListMeta)
	}
	if in.Status != "" {
		const prefix string = ",\"status\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Status))
	}
	if in.Message != "" {
		const prefix string = ",\"message\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Message))
	}
	if in.Reason != "" {
		const prefix string = ",\"reason\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Reason))
	}
	if in.Details != nil {
		const prefix string = ",\"details\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson5(out, *in.Details)
	}
	if in.Code != 0 {
		const prefix string = ",\"code\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.Code))
	}
	if in.Kind != "" {
		const prefix string = ",\"kind\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Kind))
	}
	if in.APIVersion != "" {
		const prefix string = ",\"apiVersion\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.APIVersion))
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson5(in *jlexer.Lexer, out *StatusDetails) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "name":
			out.Name = string(in.String())
		case "group":
			out.Group = string(in.String())
		case "kind":
			out.Kind = string(in.String())
		case "uid":
			out.UID = UID(in.String())
		case "causes":
			if in.IsNull() {
				in.Skip()
				out.Causes = nil
			} else {
				in.Delim('[')
				if out.Causes == nil {
					if !in.IsDelim(']') {
						out.Causes = make([]StatusCause, 0, 1)
					} else {
						out.Causes = []StatusCause{}
					}
				} else {
					out.Causes = (out.Causes)[:0]
				}
				for !in.IsDelim(']') {
					var v9 StatusCause
					easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson6(in, &v9)
					out.Causes = append(out.Causes, v9)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "retryAfterSeconds":
			out.RetryAfterSeconds = int32(in.Int32())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson5(out *jwriter.Writer, in StatusDetails) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Name != "" {
		const prefix string = ",\"name\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	if in.Group != "" {
		const prefix string = ",\"group\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Group))
	}
	if in.Kind != "" {
		const prefix string = ",\"kind\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Kind))
	}
	if in.UID != "" {
		const prefix string = ",\"uid\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.UID))
	}
	if len(in.Causes) != 0 {
		const prefix string = ",\"causes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v10, v11 := range in.Causes {
				if v10 > 0 {
					out.RawByte(',')
				}
				easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson6(out, v11)
			}
			out.RawByte(']')
		}
	}
	if in.RetryAfterSeconds != 0 {
		const prefix string = ",\"retryAfterSeconds\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.RetryAfterSeconds))
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson6(in *jlexer.Lexer, out *StatusCause) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "reason":
			out.Type = CauseType(in.String())
		case "message":
			out.Message = string(in.String())
		case "field":
			out.Field = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson6(out *jwriter.Writer, in StatusCause) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Type != "" {
		const prefix string = ",\"reason\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Type))
	}
	if in.Message != "" {
		const prefix string = ",\"message\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Message))
	}
	if in.Field != "" {
		const prefix string = ",\"field\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Field))
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson4(in *jlexer.Lexer, out *ListMeta) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "selfLink":
			out.SelfLink = string(in.String())
		case "resourceVersion":
			out.ResourceVersion = string(in.String())
		case "continue":
			out.Continue = string(in.String())
		case "remainingItemCount":
			if in.IsNull() {
				in.Skip()
				out.RemainingItemCount = nil
			} else {
				if out.RemainingItemCount == nil {
					out.RemainingItemCount = new(int64)
				}
				*out.RemainingItemCount = int64(in.Int64())
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson4(out *jwriter.Writer, in ListMeta) {
	out.RawByte('{')
	first := true
	_ = first
	if in.SelfLink != "" {
		const prefix string = ",\"selfLink\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.SelfLink))
	}
	if in.ResourceVersion != "" {
		const prefix string = ",\"resourceVersion\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.ResourceVersion))
	}
	if in.Continue != "" {
		const prefix string = ",\"continue\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Continue))
	}
	if in.RemainingItemCount != nil {
		const prefix string = ",\"remainingItemCount\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(*in.RemainingItemCount))
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson1(in *jlexer.Lexer, out *AdmissionRequest) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "uid":
			out.UID = UID(in.String())
		case "kind":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(in, &out.Kind)
		case "resource":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(in, &out.Resource)
		case "subResource":
			out.SubResource = string(in.String())
		case "requestKind":
			if in.IsNull() {
				in.Skip()
				out.RequestKind = nil
			} else {
				if out.RequestKind == nil {
					out.RequestKind = new(GroupVersionKind)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(in, out.RequestKind)
			}
		case "requestResource":
			if in.IsNull() {
				in.Skip()
				out.RequestResource = nil
			} else {
				if out.RequestResource == nil {
					out.RequestResource = new(GroupVersionResource)
				}
				easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(in, out.RequestResource)
			}
		case "requestSubResource":
			out.RequestSubResource = string(in.String())
		case "name":
			out.Name = string(in.String())
		case "namespace":
			out.Namespace = string(in.String())
		case "operation":
			out.Operation = Operation(in.String())
		case "userInfo":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson9(in, &out.UserInfo)
		case "object":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(in, &out.Object)
		case "oldObject":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(in, &out.OldObject)
		case "dryRun":
			if in.IsNull() {
				in.Skip()
				out.DryRun = nil
			} else {
				if out.DryRun == nil {
					out.DryRun = new(bool)
				}
				*out.DryRun = bool(in.Bool())
			}
		case "options":
			easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(in, &out.Options)
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson1(out *jwriter.Writer, in AdmissionRequest) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"uid\":"
		out.RawString(prefix[1:])
		out.String(string(in.UID))
	}
	{
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(out, in.Kind)
	}
	{
		const prefix string = ",\"resource\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(out, in.Resource)
	}
	if in.SubResource != "" {
		const prefix string = ",\"subResource\":"
		out.RawString(prefix)
		out.String(string(in.SubResource))
	}
	if in.RequestKind != nil {
		const prefix string = ",\"requestKind\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(out, *in.RequestKind)
	}
	if in.RequestResource != nil {
		const prefix string = ",\"requestResource\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(out, *in.RequestResource)
	}
	if in.RequestSubResource != "" {
		const prefix string = ",\"requestSubResource\":"
		out.RawString(prefix)
		out.String(string(in.RequestSubResource))
	}
	if in.Name != "" {
		const prefix string = ",\"name\":"
		out.RawString(prefix)
		out.String(string(in.Name))
	}
	if in.Namespace != "" {
		const prefix string = ",\"namespace\":"
		out.RawString(prefix)
		out.String(string(in.Namespace))
	}
	{
		const prefix string = ",\"operation\":"
		out.RawString(prefix)
		out.String(string(in.Operation))
	}
	{
		const prefix string = ",\"userInfo\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson9(out, in.UserInfo)
	}
	if true {
		const prefix string = ",\"object\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(out, in.Object)
	}
	if true {
		const prefix string = ",\"oldObject\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(out, in.OldObject)
	}
	if in.DryRun != nil {
		const prefix string = ",\"dryRun\":"
		out.RawString(prefix)
		out.Bool(bool(*in.DryRun))
	}
	if true {
		const prefix string = ",\"options\":"
		out.RawString(prefix)
		easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(out, in.Options)
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(in *jlexer.Lexer, out *RawExtension) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson10(out *jwriter.Writer, in RawExtension) {
	out.RawByte('{')
	first := true
	_ = first
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson9(in *jlexer.Lexer, out *UserInfo) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "username":
			out.Username = string(in.String())
		case "uid":
			out.UID = string(in.String())
		case "groups":
			if in.IsNull() {
				in.Skip()
				out.Groups = nil
			} else {
				in.Delim('[')
				if out.Groups == nil {
					if !in.IsDelim(']') {
						out.Groups = make([]string, 0, 4)
					} else {
						out.Groups = []string{}
					}
				} else {
					out.Groups = (out.Groups)[:0]
				}
				for !in.IsDelim(']') {
					var v12 string
					v12 = string(in.String())
					out.Groups = append(out.Groups, v12)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "extra":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Extra = make(map[string]ExtraValue)
				} else {
					out.Extra = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v13 ExtraValue
					if in.IsNull() {
						in.Skip()
						v13 = nil
					} else {
						in.Delim('[')
						if v13 == nil {
							if !in.IsDelim(']') {
								v13 = make(ExtraValue, 0, 4)
							} else {
								v13 = ExtraValue{}
							}
						} else {
							v13 = (v13)[:0]
						}
						for !in.IsDelim(']') {
							var v14 string
							v14 = string(in.String())
							v13 = append(v13, v14)
							in.WantComma()
						}
						in.Delim(']')
					}
					(out.Extra)[key] = v13
					in.WantComma()
				}
				in.Delim('}')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson9(out *jwriter.Writer, in UserInfo) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Username != "" {
		const prefix string = ",\"username\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Username))
	}
	if in.UID != "" {
		const prefix string = ",\"uid\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.UID))
	}
	if len(in.Groups) != 0 {
		const prefix string = ",\"groups\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v15, v16 := range in.Groups {
				if v15 > 0 {
					out.RawByte(',')
				}
				out.String(string(v16))
			}
			out.RawByte(']')
		}
	}
	if len(in.Extra) != 0 {
		const prefix string = ",\"extra\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('{')
			v17First := true
			for v17Name, v17Value := range in.Extra {
				if v17First {
					v17First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v17Name))
				out.RawByte(':')
				if v17Value == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
					out.RawString("null")
				} else {
					out.RawByte('[')
					for v18, v19 := range v17Value {
						if v18 > 0 {
							out.RawByte(',')
						}
						out.String(string(v19))
					}
					out.RawByte(']')
				}
			}
			out.RawByte('}')
		}
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(in *jlexer.Lexer, out *GroupVersionResource) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "group":
			out.Group = string(in.String())
		case "version":
			out.Version = string(in.String())
		case "resource":
			out.Resource = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson8(out *jwriter.Writer, in GroupVersionResource) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"group\":"
		out.RawString(prefix[1:])
		out.String(string(in.Group))
	}
	{
		const prefix string = ",\"version\":"
		out.RawString(prefix)
		out.String(string(in.Version))
	}
	{
		const prefix string = ",\"resource\":"
		out.RawString(prefix)
		out.String(string(in.Resource))
	}
	out.RawByte('}')
}
func easyjsonEf7a56cdDecodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(in *jlexer.Lexer, out *GroupVersionKind) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "group":
			out.Group = string(in.String())
		case "version":
			out.Version = string(in.String())
		case "kind":
			out.Kind = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonEf7a56cdEncodeK8sIoApiserverPkgAdmissionPluginWasmValidatingJson7(out *jwriter.Writer, in GroupVersionKind) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"group\":"
		out.RawString(prefix[1:])
		out.String(string(in.Group))
	}
	{
		const prefix string = ",\"version\":"
		out.RawString(prefix)
		out.String(string(in.Version))
	}
	{
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		out.String(string(in.Kind))
	}
	out.RawByte('}')
}
