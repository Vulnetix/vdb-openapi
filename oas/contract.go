// Package oas is the data contract every Vulnetix service reads an API
// description through. A Swagger 2.0, OpenAPI 3.0 or OpenAPI 3.1 file all
// become the same Document, so a consumer never branches on spec version.
//
// The contract is a summary, not a round-trippable model. It keeps what
// correlation, liveness, robustness scoring and regression testing need and
// says, in Losses, what it could not carry. A consumer that needs the
// original document keeps the bytes; Source.SHA256 names them.
//
// JSON field names are part of the contract. Renaming or removing one is a
// breaking change and bumps ContractVersion's major.
package oas

// ContractVersion is the version of this data contract, independent of the
// module's own tag. Consumers that persist Documents store it beside them.
const ContractVersion = "1.0.0"

// Format names the family of the input document.
type Format string

const (
	FormatSwagger Format = "swagger"
	FormatOpenAPI Format = "openapi"
)

// Document is one API description in contract form.
type Document struct {
	Contract        string                    `json:"contract"`
	Source          Source                    `json:"source"`
	Info            Info                      `json:"info"`
	Servers         []Server                  `json:"servers"`
	Operations      []Operation               `json:"operations"`
	Webhooks        []Operation               `json:"webhooks"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes"`
	Tags            []string                  `json:"tags"`
	Losses          []Loss                    `json:"losses"`
	Issues          []Issue                   `json:"issues"`
}

// Source describes the bytes the Document was read from.
type Source struct {
	Format      Format `json:"format"`
	SpecVersion string `json:"specVersion"`
	// Encoding is "json" or "yaml".
	Encoding string `json:"encoding"`
	SHA256   string `json:"sha256"`
	Path     string `json:"path,omitempty"`
}

type Info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
	Summary string `json:"summary,omitempty"`
}

// Server is one base URL. URL keeps any {variable} as written; Resolved
// substitutes each variable's default. BasePath is the path part of
// Resolved, which is what a live request path starts with.
type Server struct {
	URL       string                    `json:"url"`
	Resolved  string                    `json:"resolved"`
	BasePath  string                    `json:"basePath"`
	Scheme    string                    `json:"scheme,omitempty"`
	Host      string                    `json:"host,omitempty"`
	Variables map[string]ServerVariable `json:"variables,omitempty"`
}

type ServerVariable struct {
	Default string   `json:"default"`
	Enum    []string `json:"enum,omitempty"`
}

// Operation is one method on one path.
type Operation struct {
	Method string `json:"method"`
	// PathTemplate is the path as the document writes it, relative to the
	// servers. For a webhook it is empty and Webhook names it.
	PathTemplate string `json:"pathTemplate"`
	// Key is the normalised "METHOD /path/{param}" that code routes from the
	// CLI use too, so a spec operation and a code route meet on it.
	Key         string            `json:"key"`
	Webhook     string            `json:"webhook,omitempty"`
	OperationID string            `json:"operationId,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Tags        []string          `json:"tags"`
	Deprecated  bool              `json:"deprecated"`
	Parameters  []Parameter       `json:"parameters"`
	RequestBody *RequestBody      `json:"requestBody"`
	Responses   []Response        `json:"responses"`
	Security    Security          `json:"security"`
	Servers     []Server          `json:"servers"`
	Callbacks   []string          `json:"callbacks"`
	Extensions  map[string]string `json:"extensions,omitempty"`
	PIIHints    []PIIHint         `json:"piiHints"`
}

// ParameterIn is where a parameter travels.
type ParameterIn string

const (
	InPath   ParameterIn = "path"
	InQuery  ParameterIn = "query"
	InHeader ParameterIn = "header"
	InCookie ParameterIn = "cookie"
)

// Parameter is a non-body input. Style and Explode are always filled with
// the effective value, defaults included, so two documents that mean the
// same serialisation compare equal.
type Parameter struct {
	Name          string        `json:"name"`
	In            ParameterIn   `json:"in"`
	Required      bool          `json:"required"`
	Deprecated    bool          `json:"deprecated"`
	Style         string        `json:"style"`
	Explode       bool          `json:"explode"`
	AllowReserved bool          `json:"allowReserved"`
	Schema        SchemaSummary `json:"schema"`
	// Example is the first example the document gives (parameter, then
	// schema example, default or first enum value), as text, at most 200
	// characters. Empty when there is none.
	Example string `json:"example,omitempty"`
}

type RequestBody struct {
	Required bool        `json:"required"`
	Content  []MediaType `json:"content"`
}

// MediaType is one content type and its schema. Content lists are sorted
// by Type.
type MediaType struct {
	Type   string         `json:"type"`
	Schema *SchemaSummary `json:"schema"`
	// Encoding holds, per multipart or form field, the content types the
	// document allows for that field.
	Encoding map[string]string `json:"encoding,omitempty"`
}

type Response struct {
	// Code is the status code as written ("200", "4XX", "default").
	Code    string      `json:"code"`
	Content []MediaType `json:"content"`
	Headers []string    `json:"headers"`
}

// SecurityState says what the document declares about authentication for
// one operation. Unspecified (nothing declared anywhere) is not None (the
// document says no authentication); a consumer must never read one as the
// other.
type SecurityState string

const (
	SecurityRequired    SecurityState = "required"
	SecurityOptional    SecurityState = "optional"
	SecurityNone        SecurityState = "none"
	SecurityUnspecified SecurityState = "unspecified"
)

// Security is the effective requirement after document defaults.
type Security struct {
	State SecurityState `json:"state"`
	// From is "operation", "document" or "" when unspecified.
	From string `json:"from"`
	// Alternatives: any one entry satisfies the operation; every scheme in
	// an entry is needed together. Sorted for comparison.
	Alternatives [][]SchemeUse `json:"alternatives"`
}

type SchemeUse struct {
	Scheme string   `json:"scheme"`
	Scopes []string `json:"scopes"`
}

// SecurityScheme types follow OpenAPI 3: apiKey, http, oauth2,
// openIdConnect, mutualTLS. Swagger 2.0 "basic" becomes http/basic.
type SecurityScheme struct {
	Type             string      `json:"type"`
	Scheme           string      `json:"scheme,omitempty"`
	BearerFormat     string      `json:"bearerFormat,omitempty"`
	In               ParameterIn `json:"in,omitempty"`
	Name             string      `json:"name,omitempty"`
	Flows            []OAuthFlow `json:"flows,omitempty"`
	OpenIDConnectURL string      `json:"openIdConnectUrl,omitempty"`
}

// OAuthFlow kinds follow OpenAPI 3: implicit, password, clientCredentials,
// authorizationCode.
type OAuthFlow struct {
	Kind             string   `json:"kind"`
	AuthorizationURL string   `json:"authorizationUrl,omitempty"`
	TokenURL         string   `json:"tokenUrl,omitempty"`
	Scopes           []string `json:"scopes"`
}

// SchemaSummary keeps the constraints that decide what a server is told to
// accept. Unset limits are nil, never zero: a consumer must be able to tell
// "maxLength: 0" from "no maxLength".
type SchemaSummary struct {
	// Name is the component the schema came from through a $ref, if any.
	Name string `json:"name,omitempty"`
	// Type is the one non-null JSON type, or "" when the schema allows
	// several (then Types lists them) or does not say.
	Type     string   `json:"type"`
	Types    []string `json:"types,omitempty"`
	Format   string   `json:"format,omitempty"`
	Nullable bool     `json:"nullable,omitempty"`

	Enum      []string `json:"enum,omitempty"`
	EnumCount int      `json:"enumCount,omitempty"`

	MinLength *int   `json:"minLength,omitempty"`
	MaxLength *int   `json:"maxLength,omitempty"`
	Pattern   string `json:"pattern,omitempty"`

	Minimum          *float64 `json:"minimum,omitempty"`
	Maximum          *float64 `json:"maximum,omitempty"`
	ExclusiveMinimum bool     `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum bool     `json:"exclusiveMaximum,omitempty"`
	MultipleOf       *float64 `json:"multipleOf,omitempty"`

	MinItems    *int           `json:"minItems,omitempty"`
	MaxItems    *int           `json:"maxItems,omitempty"`
	UniqueItems bool           `json:"uniqueItems,omitempty"`
	Items       *SchemaSummary `json:"items,omitempty"`

	Properties map[string]SchemaSummary `json:"properties,omitempty"`
	Required   []string                 `json:"required,omitempty"`
	// AdditionalProperties is nil when the document does not say (JSON
	// Schema then allows any), false when closed, true when open.
	AdditionalProperties *bool `json:"additionalProperties,omitempty"`
	MaxProperties        *int  `json:"maxProperties,omitempty"`

	// Variants holds oneOf and anyOf branches. allOf is merged into the
	// schema itself.
	Variants []SchemaSummary `json:"variants,omitempty"`

	ContentMediaType string `json:"contentMediaType,omitempty"`
	ContentEncoding  string `json:"contentEncoding,omitempty"`
	ReadOnly         bool   `json:"readOnly,omitempty"`
	WriteOnly        bool   `json:"writeOnly,omitempty"`

	// Recursive marks a schema that refers back to one of its parents; the
	// summary stops there instead of repeating.
	Recursive bool `json:"recursive,omitempty"`
	// Truncated marks a schema cut at the depth or width cap.
	Truncated bool `json:"truncated,omitempty"`
}

// PIIHint marks an input or output whose name suggests personal or
// credential data. Where is "query:email", "body:user.email" or
// "response:200:ssn".
type PIIHint struct {
	Kind  string `json:"kind"`
	Where string `json:"where"`
}

// Loss is a construct the contract could not carry. Pointer is a JSON
// pointer into the source document.
type Loss struct {
	Pointer   string `json:"pointer"`
	Construct string `json:"construct"`
	Reason    string `json:"reason"`
}

// Issue is a structural problem found while reading.
type Issue struct {
	Pointer  string `json:"pointer"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}
