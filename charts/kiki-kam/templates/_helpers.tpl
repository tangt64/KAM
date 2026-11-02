{{- define "kam.validate" -}}
{{- if ne .Release.Namespace "kam-system" }}{{ fail "Install into the protected kam-system namespace" }}{{ end -}}
{{- if .Values.auth.enabled -}}
{{- $image := required "auth.image is required" .Values.auth.image -}}
{{- $audience := required "auth.audience must match the existing API audience" .Values.auth.audience -}}
{{- if regexMatch "\\s" $audience }}{{ fail "API audience cannot contain whitespace" }}{{ end -}}
{{- if and (not .Values.local.allowUnpinnedImages) (not (regexMatch "^[^\\s]+@sha256:[a-f0-9]{64}$" $image)) }}{{ fail "auth.image requires a SHA-256 digest; only explicit local mode allows tags" }}{{ end -}}
{{- if and .Values.local.allowUnpinnedImages (not (regexMatch "^[^\\s]+$" $image)) }}{{ fail "Invalid auth.image" }}{{ end -}}
{{- if and (eq .Values.auth.service.type "NodePort") (not .Values.auth.service.nodePort) }}{{ fail "NodePort requires auth.service.nodePort" }}{{ end -}}
{{- if and (eq .Values.auth.service.type "NodePort") (lt (int .Values.auth.service.nodePort) 30000) }}{{ fail "NodePort must be in 30000..32767" }}{{ end -}}
{{- if hasPrefix "REPLACE_" $audience }}{{ fail "Replace the API audience placeholder" }}{{ end -}}
{{- if and (eq .Values.auth.service.type "ClusterIP") .Values.auth.service.nodePort }}{{ fail "ClusterIP cannot specify nodePort" }}{{ end -}}
{{- end -}}
{{- if not (regexMatch "^[^\\s]+@sha256:[a-f0-9]{64}$" .Values.controller.image) }}{{ fail "controller.image requires a SHA-256 digest" }}{{ end -}}
{{- $seen := dict -}}
{{- range .Values.controller.targets -}}
{{- if or (has .namespace (list "default" "kam-system")) (hasPrefix "kube-" .namespace) }}{{ fail "Target namespace must not be default, kam-system or kube-*" }}{{ end -}}
{{- if hasKey $seen .namespace }}{{ fail "Duplicate controller target namespace" }}{{ end -}}
{{- $_ := set $seen .namespace true -}}
{{- end -}}
{{- end -}}
