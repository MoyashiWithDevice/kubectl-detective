{{/*
Expand the name of the chart.
*/}}
{{- define "kubectl-detective.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kubectl-detective.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubectl-detective.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubectl-detective.labels" -}}
helm.sh/chart: {{ include "kubectl-detective.chart" . }}
{{ include "kubectl-detective.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the aggregator
*/}}
{{- define "kubectl-detective.aggregatorSelectorLabels" -}}
app.kubernetes.io/name: detective
app.kubernetes.io/component: aggregator
{{- end }}

{{/*
Selector labels for the agent
*/}}
{{- define "kubectl-detective.agentSelectorLabels" -}}
app.kubernetes.io/name: detective
app.kubernetes.io/component: agent
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubectl-detective.selectorLabels" -}}
app.kubernetes.io/name: detective
app.kubernetes.io/component: aggregator
{{- end }}

{{/*
Namespace
*/}}
{{- define "kubectl-detective.namespace" -}}
{{- if .Values.namespaceOverride }}
{{- .Values.namespaceOverride }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}
