{{/*
OpenDirectory Helm chart helpers
*/}}

{{/* Expand the name of the chart. */}}
{{- define "opendirectory.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "opendirectory.fullname" -}}
{{- if .Values.global.fullnameOverride }}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.global.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Create chart label. */}}
{{- define "opendirectory.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "opendirectory.labels" -}}
helm.sh/chart: {{ include "opendirectory.chart" . }}
app.kubernetes.io/name: {{ include "opendirectory.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "opendirectory.selectorLabels" -}}
app.kubernetes.io/name: {{ include "opendirectory.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Service account name */}}
{{- define "opendirectory.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.create }}
{{- default (include "opendirectory.fullname" .) .Values.rbac.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.rbac.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Namespace */}}
{{- define "opendirectory.namespace" -}}
{{- if .Values.namespace.create }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/* Image helper */}}
{{- define "opendirectory.image" -}}
{{- $registry := .root.Values.global.image.registry -}}
{{- $name := .name -}}
{{- $tag := .root.Values.global.image.tag -}}
{{- printf "%s/%s:%s" $registry $name $tag }}
{{- end }}

{{/* Prometheus annotations */}}
{{- define "opendirectory.prometheusAnnotations" -}}
{{- if .Values.prometheusAnnotations.enabled }}
prometheus.io/scrape: {{ .Values.prometheusAnnotations.scrape | quote }}
prometheus.io/path: {{ .Values.prometheusAnnotations.path | quote }}
prometheus.io/port: {{ .Values.prometheusAnnotations.port | quote }}
{{- end }}
{{- end }}

{{/* Pod anti-affinity */}}
{{- define "opendirectory.podAntiAffinity" -}}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
