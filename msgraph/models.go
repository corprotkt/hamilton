package msgraph

import (
	"encoding/json"
	goerrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/errors"
	"github.com/manicminer/hamilton/odata"
)

type AccessPackage struct {
	ID               *string               `json:"id,omitempty"`
	Catalog          *AccessPackageCatalog `json:"catalog,omitempty"`
	CreatedDateTime  *time.Time            `json:"createdDateTime,omitempty"`
	Description      *string               `json:"description,omitempty"`
	DisplayName      *string               `json:"displayName,omitempty"`
	IsHidden         *bool                 `json:"isHidden,omitempty"`
	ModifiedDateTime *time.Time            `json:"modifiedDateTime,omitempty"`
	//Beta
	IsRoleScopesVisible *bool   `json:"isRoleScopesVisible,omitempty"`
	ModifiedBy          *string `json:"modifiedBy,omitempty"`
	CatalogId           *string `json:"catalogId,omitempty"`
	CreatedBy           *string `json:"createdBy,omitempty"`
}

type AccessPackageAssignmentPolicy struct {
	AccessPackageId         *string                   `json:"accessPackageId,omitempty"`
	AccessReviewSettings    *AssignmentReviewSettings `json:"accessReviewSettings,omitempty"`
	CanExtend               *bool                     `json:"canExtend,omitempty"`
	CreatedBy               *string                   `json:"createdBy,omitempty"`
	CreatedDateTime         *time.Time                `json:"createdDateTime,omitempty"`
	Description             *string                   `json:"description,omitempty"`
	DisplayName             *string                   `json:"displayName,omitempty"`
	DurationInDays          *int32                    `json:"durationInDays,omitempty"`
	ExpirationDateTime      *time.Time                `json:"expirationDateTime,omitempty"`
	ID                      *string                   `json:"id,omitempty"`
	ModifiedBy              *string                   `json:"modifiedBy,omitempty"`
	ModifiedDateTime        *time.Time                `json:"modifiedDateTime,omitempty"`
	RequestApprovalSettings *ApprovalSettings         `json:"requestApprovalSettings,omitempty"`
	RequestorSettings       *RequestorSettings        `json:"requestorSettings,omitempty"`
	Questions               *[]AccessPackageQuestion  `json:"questions,omitempty"`
}

type AccessPackageCatalog struct {
	ID                  *string                   `json:"id,omitempty"`
	State               AccessPackageCatalogState `json:"state,omitempty"`
	CatalogType         AccessPackageCatalogType  `json:"catalogType,omitempty"`
	CreatedDateTime     *time.Time                `json:"createdDateTime,omitempty"`
	Description         *string                   `json:"description,omitempty"`
	DisplayName         *string                   `json:"displayName,omitempty"`
	IsExternallyVisible *bool                     `json:"isExternallyVisible,omitempty"`
	ModifiedDateTime    *time.Time                `json:"modifiedDateTime,omitempty"`
	//Beta
	CatalogStatus AccessPackageCatalogStatus `json:"catalogStatus,omitempty"`
	CreatedBy     *string                    `json:"createdBy,omitempty"`
	ModifiedBy    *string                    `json:"modifiedBy,omitempty"`
}

type AccessPackageLocalizedContent struct {
	DefaultText    *string                        `json:"defaultText,omitempty"`
	LocalizedTexts *[]AccessPackageLocalizedTexts `json:"localizedTexts,omitempty"`
}

type AccessPackageLocalizedTexts struct {
	Text         *string `json:"text,omitempty"`
	LanguageCode *string `json:"languageCode,omitempty"`
}

type AccessPackageQuestion struct {
	ODataType            *odata.Type                             `json:"@odata.type,omitempty"`
	ID                   *string                                 `json:"id,omitempty"`
	IsRequired           *bool                                   `json:"isRequired,omitempty"`
	Sequence             *int32                                  `json:"sequence,omitempty"`
	Text                 *AccessPackageLocalizedContent          `json:"text,omitempty"`
	Choices              *[]AccessPackageMultipleChoiceQuestions `json:"choices,omitempty"`
	IsSingleLineQuestion *bool                                   `json:"isSingleLineQuestion,omitempty"`
}

type AccessPackageMultipleChoiceQuestions struct {
	ODataType    *odata.Type                    `json:"@odata.type,omitempty"`
	ActualValue  *string                        `json:"actualValue,string"`
	DisplayValue *AccessPackageLocalizedContent `json:"displayValue,omitempty"`
}

type AccessPackageResource struct {
	AccessPackageResourceEnvironment *AccessPackageResourceEnvironment `json:"accessPackageResourceEnvironment,omitempty"`
	AddedBy                          *string                           `json:"addedBy,omitempty"`
	AddedOn                          *time.Time                        `json:"addedOn,omitempty"`
	Description                      *bool                             `json:"description,omitempty"`
	DisplayName                      *string                           `json:"displayName,omitempty"`
	ID                               *string                           `json:"id,omitempty"`
	IsPendingOnboarding              *bool                             `json:"isPendingOnboarding,omitempty"`
	OriginId                         *string                           `json:"originId,omitempty"`
	OriginSystem                     AccessPackageResourceOriginSystem `json:"originSystem,omitempty"`
	ResourceType                     *AccessPackageResourceType        `json:"resourceType,omitempty"`
	Url                              *string                           `json:"url,omitempty"`
	// Attributes is a returned collection but is not documented or used in beta
}

type AccessPackageResourceEnvironment struct {
	ConnectionInfo       *ConnectionInfo                   `json:"connectionInfo,omitempty"`
	CreatedBy            *string                           `json:"createdBy,omitempty"`
	CreatedDateTime      *time.Time                        `json:"createdDateTime,omitempty"`
	Description          *string                           `json:"description,omitempty"`
	DisplayName          *string                           `json:"displayName,omitempty"`
	ID                   *string                           `json:"id,omitempty"`
	IsDefaultEnvironment *bool                             `json:"isDefaultEnvironment,omitempty"`
	ModifiedBy           *string                           `json:"modifiedBy,omitempty"`
	ModifiedDateTime     *time.Time                        `json:"modifiedDateTime,omitempty"`
	OriginId             *string                           `json:"originId,omitempty"`
	OriginSystem         AccessPackageResourceOriginSystem `json:"originSystem,omitempty"`
}

type AccessPackageResourceRequest struct {
	CatalogId             *string                            `json:"catalogId,omitempty"`
	ExpirationDateTime    *time.Time                         `json:"expirationDateTime,omitempty"`
	ID                    *string                            `json:"id,omitempty"`
	IsValidationOnly      *bool                              `json:"isValidationOnly,omitempty"`
	Justification         *string                            `json:"justification,omitempty"`
	RequestState          *AccessPackageResourceRequestState `json:"requestState,omitempty"`
	RequestStatus         *string                            `json:"requestStatus,omitempty"`
	RequestType           *AccessPackageResourceRequestType  `json:"requestType,omitempty"`
	AccessPackageResource *AccessPackageResource             `json:"accessPackageResource,omitempty"`
	ExecuteImmediately    *bool                              `json:"executeImmediately,omitempty"`
}

type AccessPackageResourceRole struct {
	Description           *string                           `json:"description"`
	ID                    *string                           `json:"id,omitempty"`
	DisplayName           *string                           `json:"displayName,omitempty"`
	OriginId              *string                           `json:"originId,omitempty"`
	OriginSystem          AccessPackageResourceOriginSystem `json:"originSystem,omitempty"`
	AccessPackageResource *AccessPackageResource            `json:"accessPackageResource,omitempty"`
}

type AccessPackageResourceRoleScope struct {
	AccessPackageId *string `json:"-"`

	ID                         *string                     `json:"id,omitempty"`
	CreatedBy                  *string                     `json:"createdBy,omitempty"`
	CreatedDateTime            *time.Time                  `json:"createdDateTime,omitempty"`
	ModifiedBy                 *string                     `json:"modifiedBy,omitempty"`
	ModifiedDateTime           *time.Time                  `json:"modifiedDateTime,omitempty"`
	AccessPackageResourceRole  *AccessPackageResourceRole  `json:"accessPackageResourceRole,omitempty"`
	AccessPackageResourceScope *AccessPackageResourceScope `json:"accessPackageResourceScope,omitempty"`
}

type AccessPackageResourceScope struct {
	Description  *string                           `json:"description,omitempty"`
	DisplayName  *string                           `json:"displayName,omitempty"`
	ID           *string                           `json:"id,omitempty"`
	IsRootScope  *bool                             `json:"isRootScope,omitempty"`
	OriginId     *string                           `json:"originId,omitempty"`
	OriginSystem AccessPackageResourceOriginSystem `json:"originSystem,omitempty"`
	Url          *string                           `json:"url"`
}

type AddIn struct {
	ID         *string          `json:"id,omitempty"`
	Properties *[]AddInKeyValue `json:"properties,omitempty"`
	Type       *string          `json:"type,omitempty"`
}

type AddInKeyValue struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

type AdministrativeUnit struct {
	Description *StringNullWhenEmpty          `json:"description,omitempty"`
	DisplayName *string                       `json:"displayName,omitempty"`
	ID          *string                       `json:"id,omitempty"`
	Visibility  *AdministrativeUnitVisibility `json:"visibility,omitempty"`
}

type ApiPreAuthorizedApplication struct {
	AppId         *string   `json:"appId,omitempty"`
	PermissionIds *[]string `json:"permissionIds,omitempty"`
}

type AppIdentity struct {
	AppId                *string `json:"appId,omitempty"`
	DisplayName          *string `json:"displayName,omitempty"`
	ServicePrincipalId   *string `json:"servicePrincipalId,omitempty"`
	ServicePrincipalName *string `json:"servicePrincipalName,omitempty"`
}

// Application describes an Application object.
type Application struct {
	DirectoryObject
	Owners *Owners `json:"owners@odata.bind,omitempty"`

	AddIns                        *[]AddIn                  `json:"addIns,omitempty"`
	Api                           *ApplicationApi           `json:"api,omitempty"`
	AppId                         *string                   `json:"appId,omitempty"`
	ApplicationTemplateId         *string                   `json:"applicationTemplateId,omitempty"`
	AppRoles                      *[]AppRole                `json:"appRoles,omitempty"`
	CreatedDateTime               *time.Time                `json:"createdDateTime,omitempty"`
	DefaultRedirectUri            *string                   `json:"defaultRedirectUri,omitempty"`
	DeletedDateTime               *time.Time                `json:"deletedDateTime,omitempty"`
	DisabledByMicrosoftStatus     interface{}               `json:"disabledByMicrosoftStatus,omitempty"`
	DisplayName                   *string                   `json:"displayName,omitempty"`
	GroupMembershipClaims         *[]GroupMembershipClaim   `json:"-"` // see Application.MarshalJSON / Application.UnmarshalJSON
	IdentifierUris                *[]string                 `json:"identifierUris,omitempty"`
	Info                          *InformationalUrl         `json:"info,omitempty"`
	IsAuthorizationServiceEnabled *bool                     `json:"isAuthorizationServiceEnabled,omitempty"`
	IsDeviceOnlyAuthSupported     *bool                     `json:"isDeviceOnlyAuthSupported,omitempty"`
	IsFallbackPublicClient        *bool                     `json:"isFallbackPublicClient,omitempty"`
	IsManagementRestricted        *bool                     `json:"isManagementRestricted,omitempty"`
	KeyCredentials                *[]KeyCredential          `json:"keyCredentials,omitempty"`
	Oauth2RequirePostResponse     *bool                     `json:"oauth2RequirePostResponse,omitempty"`
	OnPremisesPublishing          *OnPremisesPublishing     `json:"onPremisePublishing,omitempty"`
	OptionalClaims                *OptionalClaims           `json:"optionalClaims,omitempty"`
	ParentalControlSettings       *ParentalControlSettings  `json:"parentalControlSettings,omitempty"`
	PasswordCredentials           *[]PasswordCredential     `json:"passwordCredentials,omitempty"`
	PublicClient                  *PublicClient             `json:"publicClient,omitempty"`
	PublisherDomain               *string                   `json:"publisherDomain,omitempty"`
	RequiredResourceAccess        *[]RequiredResourceAccess `json:"requiredResourceAccess,omitempty"`
	SignInAudience                *SignInAudience           `json:"signInAudience,omitempty"`
	Spa                           *ApplicationSpa           `json:"spa,omitempty"`
	Tags                          *[]string                 `json:"tags,omitempty"`
	TokenEncryptionKeyId          *string                   `json:"tokenEncryptionKeyId,omitempty"`
	UniqueName                    *string                   `json:"uniqueName,omitempty"`
	VerifiedPublisher             *VerifiedPublisher        `json:"verifiedPublisher,omitempty"`
	Web                           *ApplicationWeb           `json:"web,omitempty"`
}

func (a Application) MarshalJSON() ([]byte, error) {
	var val *StringNullWhenEmpty
	if a.GroupMembershipClaims != nil {
		claims := make([]string, 0)
		for _, c := range *a.GroupMembershipClaims {
			claims = append(claims, string(c))
		}
		theClaims := StringNullWhenEmpty(strings.Join(claims, ","))
		val = &theClaims
	}

	// Local type needed to avoid recursive MarshalJSON calls
	type application Application
	app := struct {
		GroupMembershipClaims *StringNullWhenEmpty `json:"groupMembershipClaims,omitempty"`
		*application
	}{
		GroupMembershipClaims: val,
		application:           (*application)(&a),
	}
	buf, err := json.Marshal(&app)
	return buf, err
}

func (a *Application) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type application Application
	app := struct {
		GroupMembershipClaims *string `json:"groupMembershipClaims"`
		*application
	}{
		application: (*application)(a),
	}
	if err := json.Unmarshal(data, &app); err != nil {
		return err
	}
	if app.GroupMembershipClaims != nil {
		var groupMembershipClaims []GroupMembershipClaim
		for _, c := range strings.Split(*app.GroupMembershipClaims, ",") {
			groupMembershipClaims = append(groupMembershipClaims, GroupMembershipClaim(strings.TrimSpace(c)))
		}
		a.GroupMembershipClaims = &groupMembershipClaims
	}
	return nil
}

// AppendAppRole adds a new AppRole to an Application, checking to see if it already exists.
func (a *Application) AppendAppRole(role AppRole) error {
	if role.ID == nil {
		return goerrors.New("ID of new role is nil")
	}

	cap := 1
	if a.AppRoles != nil {
		cap += len(*a.AppRoles)
	}

	newRoles := make([]AppRole, 1, cap)
	newRoles[0] = role

	for _, v := range *a.AppRoles {
		if v.ID != nil && *v.ID == *role.ID {
			return &errors.AlreadyExistsError{Obj: "AppRole", Id: *role.ID}
		}
		newRoles = append(newRoles, v)
	}

	a.AppRoles = &newRoles
	return nil
}

// RemoveAppRole removes an AppRole from an Application.
func (a *Application) RemoveAppRole(role AppRole) error {
	if role.ID == nil {
		return goerrors.New("ID of role is nil")
	}

	if a.AppRoles == nil {
		return goerrors.New("no roles to remove")
	}

	appRoles := make([]AppRole, 0, len(*a.AppRoles))
	for _, v := range *a.AppRoles {
		if v.ID == nil || *v.ID != *role.ID {
			appRoles = append(appRoles, v)
		}
	}

	if len(appRoles) == len(*a.AppRoles) {
		return goerrors.New("could not find role to remove")
	}

	a.AppRoles = &appRoles
	return nil
}

// UpdateAppRole amends an existing AppRole defined in an Application.
func (a *Application) UpdateAppRole(role AppRole) error {
	if role.ID == nil {
		return goerrors.New("ID of role is nil")
	}

	if a.AppRoles == nil {
		return goerrors.New("no roles to update")
	}

	appRoles := *a.AppRoles
	for i, v := range appRoles {
		if v.ID != nil && *v.ID == *role.ID {
			appRoles[i] = role
			break
		}
	}

	a.AppRoles = &appRoles
	return nil
}

type ApplicationApi struct {
	AcceptMappedClaims          *bool                          `json:"acceptMappedClaims,omitempty"`
	KnownClientApplications     *[]string                      `json:"knownClientApplications,omitempty"`
	OAuth2PermissionScopes      *[]PermissionScope             `json:"oauth2PermissionScopes,omitempty"`
	PreAuthorizedApplications   *[]ApiPreAuthorizedApplication `json:"preAuthorizedApplications,omitempty"`
	RequestedAccessTokenVersion *int32                         `json:"requestedAccessTokenVersion,omitempty"`
}

// AppendOAuth2PermissionScope adds a new ApplicationOAuth2PermissionScope to an ApplicationApi, checking to see if it already exists.
func (a *ApplicationApi) AppendOAuth2PermissionScope(scope PermissionScope) error {
	if scope.ID == nil {
		return goerrors.New("ID of new scope is nil")
	}

	cap := 1
	if a.OAuth2PermissionScopes != nil {
		cap += len(*a.OAuth2PermissionScopes)
	}

	newScopes := make([]PermissionScope, 1, cap)
	newScopes[0] = scope

	for _, v := range *a.OAuth2PermissionScopes {
		if v.ID != nil && *v.ID == *scope.ID {
			return &errors.AlreadyExistsError{Obj: "OAuth2PermissionScope", Id: *scope.ID}
		}
		newScopes = append(newScopes, v)
	}

	a.OAuth2PermissionScopes = &newScopes
	return nil
}

// RemoveOAuth2PermissionScope removes an ApplicationOAuth2PermissionScope from an ApplicationApi.
func (a *ApplicationApi) RemoveOAuth2PermissionScope(scope PermissionScope) error {
	if scope.ID == nil {
		return goerrors.New("ID of scope is nil")
	}

	if a.OAuth2PermissionScopes == nil {
		return goerrors.New("no scopes to remove")
	}

	apiScopes := make([]PermissionScope, 0, len(*a.OAuth2PermissionScopes))
	for _, v := range *a.OAuth2PermissionScopes {
		if v.ID == nil || *v.ID != *scope.ID {
			apiScopes = append(apiScopes, v)
		}
	}

	if len(apiScopes) == len(*a.OAuth2PermissionScopes) {
		return goerrors.New("could not find scope to remove")
	}

	a.OAuth2PermissionScopes = &apiScopes
	return nil
}

// UpdateOAuth2PermissionScope amends an existing ApplicationOAuth2PermissionScope defined in an ApplicationApi.
func (a *ApplicationApi) UpdateOAuth2PermissionScope(scope PermissionScope) error {
	if scope.ID == nil {
		return goerrors.New("ID of scope is nil")
	}

	if a.OAuth2PermissionScopes == nil {
		return goerrors.New("no scopes to update")
	}

	apiScopes := *a.OAuth2PermissionScopes
	for i, v := range apiScopes {
		if v.ID != nil && *v.ID == *scope.ID {
			apiScopes[i] = scope
			break
		}
	}

	a.OAuth2PermissionScopes = &apiScopes
	return nil
}

type ApplicationEnforcedRestrictionsSessionControl struct {
	IsEnabled *bool `json:"isEnabled,omitempty"`
}

type ApplicationExtension struct {
	Id                     *string                             `json:"id,omitempty"`
	AppDisplayName         *string                             `json:"appDisplayName,omitempty"`
	DataType               ApplicationExtensionDataType        `json:"dataType,omitempty"`
	IsSyncedFromOnPremises *bool                               `json:"isSyncedFromOnPremises,omitempty"`
	Name                   *string                             `json:"name,omitempty"`
	TargetObjects          *[]ApplicationExtensionTargetObject `json:"targetObjects,omitempty"`
}

type ApplicationSpa struct {
	RedirectUris *[]string `json:"redirectUris,omitempty"`
}

type ApplicationTemplate struct {
	ID                         *string                        `json:"id,omitempty"`
	Categories                 *[]ApplicationTemplateCategory `json:"categories,omitempty"`
	Description                *string                        `json:"description,omitempty"`
	DisplayName                *string                        `json:"displayName,omitempty"`
	HomePageUrl                *string                        `json:"homePageUrl,omitempty"`
	LogoUrl                    *string                        `json:"logoUrl,omitempty"`
	Publisher                  *string                        `json:"publisher,omitempty"`
	SupportedProvisioningTypes *[]string                      `json:"supportedProvisioningTypes,omitempty"`
	SupportedSingleSignOnModes *[]string                      `json:"supportedSingleSignOnModes,omitempty"`

	Application      *Application      `json:"application,omitempty"`
	ServicePrincipal *ServicePrincipal `json:"servicePrincipal,omitempty"`
}

type ApplicationWeb struct {
	HomePageUrl           *StringNullWhenEmpty   `json:"homePageUrl,omitempty"`
	ImplicitGrantSettings *ImplicitGrantSettings `json:"implicitGrantSettings,omitempty"`
	LogoutUrl             *StringNullWhenEmpty   `json:"logoutUrl,omitempty"`
	RedirectUris          *[]string              `json:"redirectUris,omitempty"`
}

type AppliedConditionalAccessPolicy struct {
	DisplayName             *string   `json:"displayName,omitempty"`
	EnforcedGrantControls   *[]string `json:"enforcedGrantControls,omitempty"`
	EnforcedSessionControls *[]string `json:"enforcedSessionControls,omitempty"`
	Id                      *string   `json:"id,omitempty"`
	Result                  *string   `json:"appliedConditionalAccessPolicyResult,omitempty"`
}

type AppRole struct {
	ID                 *string                     `json:"id,omitempty"`
	AllowedMemberTypes *[]AppRoleAllowedMemberType `json:"allowedMemberTypes,omitempty"`
	Description        *string                     `json:"description,omitempty"`
	DisplayName        *string                     `json:"displayName,omitempty"`
	IsEnabled          *bool                       `json:"isEnabled,omitempty"`
	Origin             *string                     `json:"origin,omitempty"`
	Value              *string                     `json:"value,omitempty"`
}

type AppRoleAssignment struct {
	Id                   *string    `json:"id,omitempty"`
	DeletedDateTime      *time.Time `json:"deletedDateTime,omitempty"`
	AppRoleId            *string    `json:"appRoleId,omitempty"`
	CreatedDateTime      *time.Time `json:"createdDateTime,omitempty"`
	PrincipalDisplayName *string    `json:"principalDisplayName,omitempty"`
	PrincipalId          *string    `json:"principalId,omitempty"`
	PrincipalType        *string    `json:"principalType,omitempty"`
	ResourceDisplayName  *string    `json:"resourceDisplayName,omitempty"`
	ResourceId           *string    `json:"resourceId,omitempty"`
}

type ApprovalSettings struct {
	IsApprovalRequired               *bool            `json:"isApprovalRequired,omitempty"`
	IsApprovalRequiredForExtension   *bool            `json:"isApprovalRequiredForExtension,omitempty"`
	IsRequestorJustificationRequired *bool            `json:"isRequestorJustificationRequired,omitempty"`
	ApprovalMode                     ApprovalMode     `json:"approvalMode,omitempty"`
	ApprovalStages                   *[]ApprovalStage `json:"approvalStages,omitempty"`
}

type ApprovalStage struct {
	ApprovalStageTimeOutInDays      *int32     `json:"approvalStageTimeOutInDays,omitempty"`
	IsApproverJustificationRequired *bool      `json:"isApproverJustificationRequired,omitempty"`
	IsEscalationEnabled             *bool      `json:"isEscalationEnabled,omitempty"`
	EscalationTimeInMinutes         *int32     `json:"escalationTimeInMinutes,omitempty"`
	PrimaryApprovers                *[]UserSet `json:"primaryApprovers,omitempty"`
	EscalationApprovers             *[]UserSet `json:"escalationApprovers,omitempty"`
}

type AssignmentReviewSettings struct {
	IsEnabled                       *bool                           `json:"isEnabled,omitempty"`
	RecurrenceType                  AccessReviewRecurranceType      `json:"recurrenceType,omitempty"`
	ReviewerType                    AccessReviewReviewerType        `json:"reviewerType,omitempty"`
	StartDateTime                   *time.Time                      `json:"startDateTime,omitempty"`
	DurationInDays                  *int32                          `json:"durationInDays,omitempty"`
	Reviewers                       *[]UserSet                      `json:"reviewers,omitempty"`
	IsAccessRecommendationEnabled   *bool                           `json:"isAccessRecommendationEnabled,omitempty"`
	IsApprovalJustificationRequired *bool                           `json:"isApprovalJustificationRequired,omitempty"`
	AccessReviewTimeoutBehavior     AccessReviewTimeoutBehaviorType `json:"accessReviewTimeoutBehavior,omitempty"`
}

type AuditActivityInitiator struct {
	App  *AppIdentity  `json:"app,omitempty"`
	User *UserIdentity `json:"user,omitempty"`
}

type AuthenticationMethod interface{}

type BaseNamedLocation struct {
	ODataType        *odata.Type `json:"@odata.type,omitempty"`
	ID               *string     `json:"id,omitempty"`
	DisplayName      *string     `json:"displayName,omitempty"`
	CreatedDateTime  *time.Time  `json:"createdDateTime,omitempty"`
	ModifiedDateTime *time.Time  `json:"modifiedDateTime,omitempty"`
}

type ClaimsMappingPolicy struct {
	DirectoryObject
	Definition            *[]string `json:"definition,omitempty"`
	Description           *string   `json:"description,omitempty"`
	DisplayName           *string   `json:"displayName,omitempty"`
	IsOrganizationDefault *bool     `json:"isOrganizationDefault,omitempty"`
}

type CloudAppSecurityControl struct {
	IsEnabled            *bool                                                `json:"isEnabled,omitempty"`
	CloudAppSecurityType *ConditionalAccessCloudAppSecuritySessionControlType `json:"cloudAppSecurityType,omitempty"`
}

type ConditionalAccessApplications struct {
	IncludeApplications *[]string `json:"includeApplications,omitempty"`
	ExcludeApplications *[]string `json:"excludeApplications,omitempty"`
	IncludeUserActions  *[]string `json:"includeUserActions,omitempty"`
}

type ConditionalAccessConditionSet struct {
	Applications     *ConditionalAccessApplications    `json:"applications,omitempty"`
	ClientAppTypes   *[]ConditionalAccessClientAppType `json:"clientAppTypes,omitempty"`
	Devices          *ConditionalAccessDevices         `json:"devices,omitempty"`
	DeviceStates     *ConditionalAccessDeviceStates    `json:"deviceStates,omitempty"`
	Locations        *ConditionalAccessLocations       `json:"locations,omitempty"`
	Platforms        *ConditionalAccessPlatforms       `json:"platforms,omitempty"`
	SignInRiskLevels *[]ConditionalAccessRiskLevel     `json:"signInRiskLevels,omitempty"`
	UserRiskLevels   *[]ConditionalAccessRiskLevel     `json:"userRiskLevels,omitempty"`
	Users            *ConditionalAccessUsers           `json:"users,omitempty"`
}

type ConditionalAccessDevices struct {
	IncludeDevices *[]string                `json:"includeDevices,omitempty"`
	ExcludeDevices *[]string                `json:"excludeDevices,omitempty"`
	DeviceFilter   *ConditionalAccessFilter `json:"deviceFilter,omitempty"`
}

type ConditionalAccessDeviceStates struct {
	IncludeStates *ConditionalAccessDeviceStatesInclude `json:"includeStates,omitempty"`
	ExcludeStates *ConditionalAccessDeviceStatesExclude `json:"excludeStates,omitempty"`
}

type ConditionalAccessFilter struct {
	Mode *ConditionalAccessFilterMode `json:"mode,omitempty"`
	Rule *string                      `json:"rule,omitempty"`
}

type ConditionalAccessGrantControls struct {
	Operator                    *string                          `json:"operator,omitempty"`
	BuiltInControls             *[]ConditionalAccessGrantControl `json:"builtInControls,omitempty"`
	CustomAuthenticationFactors *[]string                        `json:"customAuthenticationFactors,omitempty"`
	TermsOfUse                  *[]string                        `json:"termsOfUse,omitempty"`
}

type ConditionalAccessLocations struct {
	IncludeLocations *[]string `json:"includeLocations,omitempty"`
	ExcludeLocations *[]string `json:"excludeLocations,omitempty"`
}

type ConditionalAccessPlatforms struct {
	IncludePlatforms *[]ConditionalAccessDevicePlatform `json:"includePlatforms,omitempty"`
	ExcludePlatforms *[]ConditionalAccessDevicePlatform `json:"excludePlatforms,omitempty"`
}

// ConditionalAccessPolicy describes an Conditional Access Policy object.
type ConditionalAccessPolicy struct {
	Conditions       *ConditionalAccessConditionSet    `json:"conditions,omitempty"`
	CreatedDateTime  *time.Time                        `json:"createdDateTime,omitempty"`
	DisplayName      *string                           `json:"displayName,omitempty"`
	GrantControls    *ConditionalAccessGrantControls   `json:"grantControls,omitempty"`
	ID               *string                           `json:"id,omitempty"`
	ModifiedDateTime *time.Time                        `json:"modifiedDateTime,omitempty"`
	SessionControls  *ConditionalAccessSessionControls `json:"sessionControls,omitempty"`
	State            *ConditionalAccessPolicyState     `json:"state,omitempty"`
}

type ConditionalAccessSessionControls struct {
	ApplicationEnforcedRestrictions *ApplicationEnforcedRestrictionsSessionControl `json:"applicationEnforcedRestrictions,omitempty"`
	CloudAppSecurity                *CloudAppSecurityControl                       `json:"cloudAppSecurity,omitempty"`
	PersistentBrowser               *PersistentBrowserSessionControl               `json:"persistentBrowser,omitempty"`
	SignInFrequency                 *SignInFrequencySessionControl                 `json:"signInFrequency,omitempty"`
}

type ConditionalAccessUsers struct {
	IncludeUsers  *[]string `json:"includeUsers,omitempty"`
	ExcludeUsers  *[]string `json:"excludeUsers,omitempty"`
	IncludeGroups *[]string `json:"includeGroups,omitempty"`
	ExcludeGroups *[]string `json:"excludeGroups,omitempty"`
	IncludeRoles  *[]string `json:"includeRoles,omitempty"`
	ExcludeRoles  *[]string `json:"excludeRoles,omitempty"`
}

type ConnectionInfo struct {
	Url *string `json:"url,omitempty"`
}

// CountryNamedLocation describes an Country Named Location object.
type CountryNamedLocation struct {
	*BaseNamedLocation
	CountriesAndRegions               *[]string `json:"countriesAndRegions,omitempty"`
	IncludeUnknownCountriesAndRegions *bool     `json:"includeUnknownCountriesAndRegions,omitempty"`
}

type CredentialUserRegistrationCount struct {
	ID                     *string                  `json:"id,omitempty"`
	TotalUserCount         *int64                   `json:"totalUserCount,omitempty"`
	UserRegistrationCounts *[]UserRegistrationCount `json:"userRegistrationCounts,omitempty"`
}

type CredentialUsageSummary struct {
	AuthMethod              *UsageAuthMethod `json:"usageAuthMethod,omitempty"`
	FailureActivityCount    *int64           `json:"failureActivityCount,omitempty"`
	Feature                 *FeatureType     `json:"feature,omitempty"`
	ID                      *string          `json:"id,omitempty"`
	SuccessfulActivityCount *int64           `json:"successfulActivityCount,omitempty"`
}
type CredentialUserRegistrationDetails struct {
	AuthMethods       *[]RegistrationAuthMethod `json:"authMethods,omitempty"`
	ID                *string                   `json:"id,omitempty"`
	IsCapable         *bool                     `json:"isCapable,omitempty"`
	IsEnabled         *bool                     `json:"isEnabled,omitempty"`
	IsMfaRegistered   *bool                     `json:"isMfaRegistered,omitempty"`
	IsRegistered      *bool                     `json:"isRegistered,omitempty"`
	UserDisplayName   *string                   `json:"userDisplayName,omitempty"`
	UserPrincipalName *string                   `json:"UserPrincipalName,omitempty"`
}

type DelegatedPermissionGrant struct {
	Id          *string                              `json:"id,omitempty"`
	ClientId    *string                              `json:"clientId,omitempty"`
	ConsentType *DelegatedPermissionGrantConsentType `json:"consentType,omitempty"`
	PrincipalId *string                              `json:"principalId,omitempty"`
	ResourceId  *string                              `json:"resourceId,omitempty"`
	Scopes      *[]string                            `json:"-"`
}

func (d DelegatedPermissionGrant) MarshalJSON() ([]byte, error) {
	var val *StringNullWhenEmpty
	if d.Scopes != nil {
		scopes := make([]string, 0)
		for _, s := range *d.Scopes {
			scopes = append(scopes, string(s))
		}
		theScopes := StringNullWhenEmpty(strings.Join(scopes, " "))
		val = &theScopes
	}

	// Local type needed to avoid recursive MarshalJSON calls
	type delegatedPermissionGrant DelegatedPermissionGrant
	grant := struct {
		Scopes *StringNullWhenEmpty `json:"scope,omitempty"`
		*delegatedPermissionGrant
	}{
		Scopes:                   val,
		delegatedPermissionGrant: (*delegatedPermissionGrant)(&d),
	}
	buf, err := json.Marshal(&grant)
	return buf, err
}

func (d *DelegatedPermissionGrant) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type delegatedPermissionGrant DelegatedPermissionGrant
	grant := struct {
		Scopes *string `json:"scope"`
		*delegatedPermissionGrant
	}{
		delegatedPermissionGrant: (*delegatedPermissionGrant)(d),
	}
	if err := json.Unmarshal(data, &grant); err != nil {
		return err
	}
	if grant.Scopes != nil {
		var scopes []string
		for _, s := range strings.Split(*grant.Scopes, " ") {
			scopes = append(scopes, strings.TrimSpace(s))
		}
		d.Scopes = &scopes
	}
	return nil
}

type DeviceDetail struct {
	Browser         *string `json:"browser,omitempty"`
	DeviceId        *string `json:"deviceId,omitempty"`
	DisplayName     *string `json:"displayName,omitempty"`
	IsCompliant     *bool   `json:"isCompliant,omitempty"`
	IsManaged       *bool   `json:"isManaged,omitempty"`
	OperatingSystem *string `json:"operatingSystem,omitempty"`
	TrustType       *string `json:"trustType,omitempty"`
}

type DirectoryAudit struct {
	ActivityDateTime    *time.Time              `json:"activityDateTime,omitempty"`
	ActivityDisplayName *string                 `json:"activityDisplayName,omitempty"`
	AdditionalDetails   *[]KeyValue             `json:"additionalDetails,omitempty"`
	Category            *string                 `json:"category,omitempty"`
	CorrelationId       *string                 `json:"correlationId,omitempty"`
	Id                  *string                 `json:"id,omitempty"`
	InitiatedBy         *AuditActivityInitiator `json:"initiatedBy,omitempty"`
	LoggedByService     *string                 `json:"loggedByService,omitempty"`
	Result              *string                 `json:"result,omitempty"`
	ResultReason        *string                 `json:"resultReason,omitempty"`
	TargetResources     *[]TargetResource       `json:"targetResources,omitempty"`
}

type DirectoryObject struct {
	ODataId   *odata.Id   `json:"@odata.id,omitempty"`
	ODataType *odata.Type `json:"@odata.type,omitempty"`
	ID        *string     `json:"id,omitempty"`
}

func (o *DirectoryObject) Uri(endpoint environments.ApiEndpoint, apiVersion ApiVersion) string {
	if o.ID == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/directoryObjects/%s", endpoint, apiVersion, *o.ID)
}

type DirectoryRole struct {
	DirectoryObject
	Members *Members `json:"-"`

	Description    *string `json:"description,omitempty"`
	DisplayName    *string `json:"displayName,omitempty"`
	RoleTemplateId *string `json:"roleTemplateId,omitempty"`
}

func (r *DirectoryRole) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type directoryrole DirectoryRole
	r2 := (*directoryrole)(r)
	if err := json.Unmarshal(data, r2); err != nil {
		return err
	}
	return nil
}

// DirectoryRoleTemplate describes a Directory Role Template.
type DirectoryRoleTemplate struct {
	ID              *string    `json:"id,omitempty"`
	DeletedDateTime *time.Time `json:"deletedDateTime,omitempty"`
	Description     *string    `json:"description,omitempty"`
	DisplayName     *string    `json:"displayName,omitempty"`
}

// Domain describes a Domain object.
type Domain struct {
	ID                               *string   `json:"id,omitempty"`
	AuthenticationType               *string   `json:"authenticationType,omitempty"`
	IsAdminManaged                   *bool     `json:"isAdminManaged,omitempty"`
	IsDefault                        *bool     `json:"isDefault,omitempty"`
	IsInitial                        *bool     `json:"isInitial,omitempty"`
	IsRoot                           *bool     `json:"isRoot,omitempty"`
	IsVerified                       *bool     `json:"isVerified,omitempty"`
	PasswordNotificationWindowInDays *int      `json:"passwordNotificationWindowInDays,omitempty"`
	PasswordValidityPeriodInDays     *int      `json:"passwordValidityPeriodInDays,omitempty"`
	SupportedServices                *[]string `json:"supportedServices,omitempty"`

	State *DomainState `json:"state,omitempty"`
}

type DomainState struct {
	LastActionDateTime *time.Time `json:"lastActionDateTime,omitempty"`
	Operation          *string    `json:"operation,omitempty"`
	Status             *string    `json:"status,omitempty"`
}

type EmailAddress struct {
	Address *string `json:"address,omitempty"`
	Name    *string `json:"name,omitempty"`
}

type EmailAuthenticationMethod struct {
	ID           *string `json:"id,omitempty"`
	EmailAddress *string `json:"emailAddress,omitempty"`
}

type ExtensionSchemaProperty struct {
	Name *string                         `json:"name,omitempty"`
	Type ExtensionSchemaPropertyDataType `json:"type,omitempty"`
}

type FederatedIdentityCredential struct {
	Audiences   *[]string            `json:"audiences,omitempty"`
	Description *StringNullWhenEmpty `json:"description,omitempty"`
	ID          *string              `json:"id,omitempty"`
	Issuer      *string              `json:"issuer,omitempty"`
	Name        *string              `json:"name,omitempty"`
	Subject     *string              `json:"subject,omitempty"`
}

type Fido2AuthenticationMethod struct {
	ID                      *string           `json:"id,omitempty"`
	DisplayName             *string           `json:"displayName,omitempty"`
	CreatedDateTime         *time.Time        `json:"createdDateTime,omitempty"`
	AAGuid                  *string           `json:"aaGuid,omitempty"`
	Model                   *string           `json:"model,omitempty"`
	AttestationCertificates *[]string         `json:"attestationCertificates,omitempty"`
	AttestationLevel        *AttestationLevel `json:"attestationLevel,omitempty"`
}

type GeoCoordinates struct {
	Altitude  *float64 `json:"altitude,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}

// Group describes a Group object.
type Group struct {
	DirectoryObject
	Members          *Members               `json:"members@odata.bind,omitempty"`
	Owners           *Owners                `json:"owners@odata.bind,omitempty"`
	SchemaExtensions *[]SchemaExtensionData `json:"-"`

	AllowExternalSenders          *bool                               `json:"allowExternalSenders,omitempty"`
	AssignedLabels                *[]GroupAssignedLabel               `json:"assignedLabels,omitempty"`
	AssignedLicenses              *[]GroupAssignedLicense             `json:"assignLicenses,omitempty"`
	AutoSubscribeNewMembers       *bool                               `json:"autoSubscribeNewMembers,omitempty"`
	Classification                *string                             `json:"classification,omitempty"`
	CreatedDateTime               *time.Time                          `json:"createdDateTime,omitempty"`
	DeletedDateTime               *time.Time                          `json:"deletedDateTime,omitempty"`
	Description                   *StringNullWhenEmpty                `json:"description,omitempty"`
	DisplayName                   *string                             `json:"displayName,omitempty"`
	ExpirationDateTime            *time.Time                          `json:"expirationDateTime,omitempty"`
	GroupTypes                    []GroupType                         `json:"groupTypes,omitempty"`
	HasMembersWithLicenseErrors   *bool                               `json:"hasMembersWithLicenseErrors,omitempty"`
	HideFromAddressLists          *bool                               `json:"hideFromAddressLists,omitempty"`
	HideFromOutlookClients        *bool                               `json:"hideFromOutlookClients,omitempty"`
	IsSubscribedByMail            *bool                               `json:"isSubscribedByMail,omitempty"`
	LicenseProcessingState        *string                             `json:"licenseProcessingState,omitempty"`
	Mail                          *string                             `json:"mail,omitempty"`
	MailEnabled                   *bool                               `json:"mailEnabled,omitempty"`
	MailNickname                  *string                             `json:"mailNickname,omitempty"`
	MembershipRule                *StringNullWhenEmpty                `json:"membershipRule,omitempty"`
	MembershipRuleProcessingState *GroupMembershipRuleProcessingState `json:"membershipRuleProcessingState,omitempty"`
	OnPremisesDomainName          *string                             `json:"onPremisesDomainName,omitempty"`
	OnPremisesLastSyncDateTime    *time.Time                          `json:"onPremisesLastSyncDateTime,omitempty"`
	OnPremisesNetBiosName         *string                             `json:"onPremisesNetBiosName,omitempty"`
	OnPremisesProvisioningErrors  *[]GroupOnPremisesProvisioningError `json:"onPremisesProvisioningErrors,omitempty"`
	OnPremisesSamAccountName      *string                             `json:"onPremisesSamAccountName,omitempty"`
	OnPremisesSecurityIdentifier  *string                             `json:"onPremisesSecurityIdentifier,omitempty"`
	OnPremisesSyncEnabled         *bool                               `json:"onPremisesSyncEnabled,omitempty"`
	PreferredDataLocation         *string                             `json:"preferredDataLocation,omitempty"`
	PreferredLanguage             *string                             `json:"preferredLanguage,omitempty"`
	ProxyAddresses                *[]string                           `json:"proxyAddresses,omitempty"`
	RenewedDateTime               *time.Time                          `json:"renewedDateTime,omitempty"`
	ResourceBehaviorOptions       []GroupResourceBehaviorOption       `json:"resourceBehaviorOptions,omitempty"`
	ResourceProvisioningOptions   []GroupResourceProvisioningOption   `json:"resourceProvisioningOptions,omitempty"`
	SecurityEnabled               *bool                               `json:"securityEnabled,omitempty"`
	SecurityIdentifier            *string                             `json:"securityIdentifier,omitempty"`
	Theme                         *GroupTheme                         `json:"theme,omitempty"`
	UnseenCount                   *int                                `json:"unseenCount,omitempty"`
	Visibility                    *GroupVisibility                    `json:"visibility,omitempty"`
	IsAssignableToRole            *bool                               `json:"isAssignableToRole,omitempty"`
}

func (g Group) MarshalJSON() ([]byte, error) {
	docs := make([][]byte, 0)
	// Local type needed to avoid recursive MarshalJSON calls
	type group Group
	d, err := json.Marshal((*group)(&g))
	if err != nil {
		return d, err
	}
	docs = append(docs, d)
	if g.SchemaExtensions != nil {
		for _, se := range *g.SchemaExtensions {
			d, err := json.Marshal(se)
			if err != nil {
				return d, err
			}
			docs = append(docs, d)
		}
	}
	return MarshalDocs(docs)
}

func (g *Group) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type group Group
	g2 := (*group)(g)
	if err := json.Unmarshal(data, g2); err != nil {
		return err
	}
	if g.SchemaExtensions != nil {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for _, ext := range *g.SchemaExtensions {
			if v, ok := fields[ext.ID]; ok {
				if err := json.Unmarshal(v, &ext.Properties); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// HasTypes returns true if the group has all the specified GroupTypes
func (g *Group) HasTypes(types []GroupType) bool {
	for _, t := range types {
		found := false
		for _, gt := range g.GroupTypes {
			if t == gt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type GroupAssignedLabel struct {
	LabelId     *string `json:"labelId,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
}

type GroupAssignedLicense struct {
	DisabledPlans *[]string `json:"disabledPlans,omitempty"`
	SkuId         *string   `json:"skuId,omitempty"`
}

type GroupOnPremisesProvisioningError struct {
	Category             *string   `json:"category,omitempty"`
	OccurredDateTime     time.Time `json:"occurredDateTime,omitempty"`
	PropertyCausingError *string   `json:"propertyCausingError,omitempty"`
	Value                *string   `json:"value,omitempty"`
}

type Identity struct {
	DisplayName *string `json:"displayName,omitempty"`
	Id          *string `json:"id,omitempty"`
	TenantId    *string `json:"tenantId,omitempty"`
}

type IdentityProvider struct {
	ODataType    *odata.Type `json:"@odata.type,omitempty"`
	ID           *string     `json:"id,omitempty"`
	ClientId     *string     `json:"clientId,omitempty"`
	ClientSecret *string     `json:"clientSecret,omitempty"`
	Type         *string     `json:"identityProviderType,omitempty"`
	Name         *string     `json:"displayName,omitempty"`
}

type ImplicitGrantSettings struct {
	EnableAccessTokenIssuance *bool `json:"enableAccessTokenIssuance,omitempty"`
	EnableIdTokenIssuance     *bool `json:"enableIdTokenIssuance,omitempty"`
}

type InformationalUrl struct {
	LogoUrl             *string `json:"logoUrl,omitempty"`
	MarketingUrl        *string `json:"marketingUrl"`
	PrivacyStatementUrl *string `json:"privacyStatementUrl"`
	SupportUrl          *string `json:"supportUrl"`
	TermsOfServiceUrl   *string `json:"termsOfServiceUrl"`
}

// Invitation describes a Invitation object.
type Invitation struct {
	ID                      *string          `json:"id,omitempty"`
	InvitedUserDisplayName  *string          `json:"invitedUserDisplayName,omitempty"`
	InvitedUserEmailAddress *string          `json:"invitedUserEmailAddress,omitempty"`
	SendInvitationMessage   *bool            `json:"sendInvitationMessage,omitempty"`
	InviteRedirectURL       *string          `json:"inviteRedirectUrl,omitempty"`
	InviteRedeemURL         *string          `json:"inviteRedeemUrl,omitempty"`
	Status                  *string          `json:"status,omitempty"`
	InvitedUserType         *InvitedUserType `json:"invitedUserType,omitempty"`

	InvitedUserMessageInfo *InvitedUserMessageInfo `json:"invitedUserMessageInfo,omitempty"`
	InvitedUser            *User                   `json:"invitedUser,omitempty"`
}

type InvitedUserMessageInfo struct {
	CCRecipients          *[]Recipient `json:"ccRecipients,omitempty"`
	CustomizedMessageBody *string      `json:"customizedMessageBody,omitempty"`
	MessageLanguage       *string      `json:"messageLanguage,omitempty"`
}

// IPNamedLocation describes an IP Named Location object.
type IPNamedLocation struct {
	*BaseNamedLocation
	IPRanges  *[]IPNamedLocationIPRange `json:"ipRanges,omitempty"`
	IsTrusted *bool                     `json:"isTrusted,omitempty"`
}

type IPNamedLocationIPRange struct {
	CIDRAddress *string `json:"cidrAddress,omitempty"`
}

type ItemBody struct {
	Content     *string   `json:"content,omitempty"`
	ContentType *BodyType `json:"contentType,omitempty"`
}

type KerberosSignOnSettings struct {
	ServicePrincipalName       *string `json:"kerberosServicePrincipalName,omitempty"`
	SignOnMappingAttributeType *string `jsonL:"kerberosSignOnMappingAttributeType,omitempty"`
}

// KeyCredential describes a key (certificate) credential for an object.
type KeyCredential struct {
	CustomKeyIdentifier *string            `json:"customKeyIdentifier,omitempty"`
	DisplayName         *string            `json:"displayName,omitempty"`
	EndDateTime         *time.Time         `json:"endDateTime,omitempty"`
	KeyId               *string            `json:"keyId,omitempty"`
	StartDateTime       *time.Time         `json:"startDateTime,omitempty"`
	Type                KeyCredentialType  `json:"type"`
	Usage               KeyCredentialUsage `json:"usage"`
	Key                 *string            `json:"key,omitempty"`
}

type KeyValue struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

type Location struct {
	City            *string         `json:"city,omitempty"`
	CountryOrRegion *string         `json:"countryOrRegion,omitempty"`
	GeoCoordinates  *GeoCoordinates `json:"geoCoordinates,omitempty"`
	State           *string         `json:"state,omitempty"`
}

type MailMessage struct {
	Message *Message `json:"message,omitempty"`
}

// Me describes the authenticated user.
type Me struct {
	ID                *string `json:"id"`
	DisplayName       *string `json:"displayName"`
	UserPrincipalName *string `json:"userPrincipalName"`
}

type Message struct {
	ID            *string      `json:"id,omitempty"`
	Subject       *string      `json:"subject,omitempty"`
	Body          *ItemBody    `json:"body,omitempty"`
	From          *Recipient   `json:"from,omitempty"`
	ToRecipients  *[]Recipient `json:"toRecipients,omitempty"`
	CcRecipients  *[]Recipient `json:"ccRecipients,omitempty"`
	BccRecipients *[]Recipient `json:"bccRecipients,omitempty"`
}

type MicrosoftAuthenticatorAuthenticationMethod struct {
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	DisplayName     *string    `json:"displayName,omitempty"`
	ID              *string    `json:"id,omitempty"`
	DeviceTag       *string    `json:"deviceTag,omitempty"`
	PhoneAppVersion *string    `json:"phoneAppVersion,omitempty"`
}

type ModifiedProperty struct {
	DisplayName *string `json:"displayName,omitempty"`
	NewValue    *string `json:"newValue,omitempty"`
	OldValue    *string `json:"oldValue,omitempty"`
}

type NamedLocation interface{}

type OnPremisesPublishing struct {
	AlternateUrl                  *string `json:"alternateUrl,omitempty"`
	ApplicationServerTimeout      *string `json:"applicationServerTimeout,omitempty"`
	ApplicationType               *string `json:"applicationType,omitempty"`
	ExternalAuthenticationType    *string `json:"externalAuthenticationType,omitempty"`
	ExternalUrl                   *string `json:"externalUrl,omitempty"`
	InternalUrl                   *string `json:"internalUrl,omitempty"`
	IsHttpOnlyCookieEnabled       *bool   `json:"isHttpOnlyCookieEnabled,omitempty"`
	IsOnPremPublishingEnabled     *bool   `json:"isOnPremPublishingEnabled,omitempty"`
	IsPersistentCookieEnabled     *bool   `json:"isPersistentCookieEnabled,omitempty"`
	IsSecureCookieEnabled         *bool   `json:"isSecureCookieEnabled,omitempty"`
	IsTranslateHostHeaderEnabled  *bool   `json:"isTranslateHostHeaderEnabled,omitempty"`
	IsTranslateLinksInBodyEnabled *bool   `json:"isTranslateLinksInBodyEnabled,omitempty"`

	SingleSignOnSettings                     *OnPremisesPublishingSingleSignOn                             `json:"singleSignOnSettings,omitempty"`
	VerifiedCustomDomainCertificatesMetadata *OnPremisesPublishingVerifiedCustomDomainCertificatesMetadata `json:"verifiedCustomDomainCertificatesMetadata,omitempty"`
	VerifiedCustomDomainKeyCredential        *KeyCredential                                                `json:"verifiedCustomDomainKeyCredential,omitempty"`
	VerifiedCustomDomainPasswordCredential   *PasswordCredential                                           `json:"verifiedCustomDomainPasswordCredential,omitempty"`
}

type OnPremisesPublishingSingleSignOn struct {
	KerberosSignOnSettings *KerberosSignOnSettings `json:"kerberosSignOnSettings,omitempty"`
	SingleSignOnMode       *string                 `json:"singleSignOnMode,omitempty"`
}

type OnPremisesPublishingVerifiedCustomDomainCertificatesMetadata struct {
	ExpiryDate  *time.Time `json:"expiryDate,omitempty"`
	IssueDate   *time.Time `json:"issueDate,omitempty"`
	IssuerName  *string    `json:"issuerName,omitempty"`
	SubjectName *string    `json:"subjectName,omitempty"`
	Thumbprint  *string    `json:"thumbprint,omitempty"`
}

type OptionalClaim struct {
	AdditionalProperties *[]string `json:"additionalProperties,omitempty"`
	Essential            *bool     `json:"essential,omitempty"`
	Name                 *string   `json:"name,omitempty"`
	Source               *string   `json:"source,omitempty"`
}

type OptionalClaims struct {
	AccessToken *[]OptionalClaim `json:"accessToken,omitempty"`
	IdToken     *[]OptionalClaim `json:"idToken,omitempty"`
	Saml2Token  *[]OptionalClaim `json:"saml2Token,omitempty"`
}

type ParentalControlSettings struct {
	CountriesBlockedForMinors *[]string `json:"countriesBlockedForMinors,omitempty"`
	LegalAgeGroupRule         *string   `json:"legalAgeGroupRule,omitempty"`
}

// PasswordCredential describes a password credential for an object.
type PasswordCredential struct {
	CustomKeyIdentifier *string    `json:"customKeyIdentifier,omitempty"`
	DisplayName         *string    `json:"displayName,omitempty"`
	EndDateTime         *time.Time `json:"endDateTime,omitempty"`
	Hint                *string    `json:"hint,omitempty"`
	KeyId               *string    `json:"keyId,omitempty"`
	SecretText          *string    `json:"secretText,omitempty"`
	StartDateTime       *time.Time `json:"startDateTime,omitempty"`
}

type PasswordAuthenticationMethod struct {
	CreationDateTime *time.Time `json:"creationDateTime,omitempty"`
	ID               *string    `json:"id,omitempty"`
	Password         *string    `json:"password,omitempty"`
}

type PasswordSingleSignOnSettings struct {
	Fields *[]SingleSignOnField `json:"fields,omitempty"`
}

type PermissionScope struct {
	ID                      *string             `json:"id,omitempty"`
	AdminConsentDescription *string             `json:"adminConsentDescription,omitempty"`
	AdminConsentDisplayName *string             `json:"adminConsentDisplayName,omitempty"`
	IsEnabled               *bool               `json:"isEnabled,omitempty"`
	Type                    PermissionScopeType `json:"type,omitempty"`
	UserConsentDescription  *string             `json:"userConsentDescription,omitempty"`
	UserConsentDisplayName  *string             `json:"userConsentDisplayName,omitempty"`
	Value                   *string             `json:"value,omitempty"`
}

type PersistentBrowserSessionControl struct {
	IsEnabled *bool                         `json:"isEnabled,omitempty"`
	Mode      *PersistentBrowserSessionMode `json:"mode,omitempty"`
}

type PhoneAuthenticationMethod struct {
	ID          *string                  `json:"id,omitempty"`
	PhoneNumber *string                  `json:"phoneNumber,omitempty"`
	PhoneType   *AuthenticationPhoneType `json:"phoneType,omitempty"`
}
type PublicClient struct {
	RedirectUris *[]string `json:"redirectUris,omitempty"`
}

type Recipient struct {
	EmailAddress *EmailAddress `json:"emailAddress,omitempty"`
}

type RequestorSettings struct {
	ScopeType         RequestorSettingsScopeType `json:"scopeType,omitempty"`
	AcceptRequests    *bool                      `json:"acceptRequests,omitempty"`
	AllowedRequestors *[]UserSet                 `json:"allowedRequestors,omitempty"`
}

type RequiredResourceAccess struct {
	ResourceAccess *[]ResourceAccess `json:"resourceAccess,omitempty"`
	ResourceAppId  *string           `json:"resourceAppId,omitempty"`
}

type ResourceAccess struct {
	ID   *string            `json:"id,omitempty"`
	Type ResourceAccessType `json:"type,omitempty"`
}

type SamlSingleSignOnSettings struct {
	RelayState *string `json:"relayState,omitempty"`
}

type SchemaExtension struct {
	ID          *string                      `json:"id,omitempty"`
	Description *string                      `json:"description,omitempty"`
	Owner       *string                      `json:"owner,omitempty"`
	Properties  *[]ExtensionSchemaProperty   `json:"properties,omitempty"`
	TargetTypes *[]ExtensionSchemaTargetType `json:"targetTypes,omitempty"`
	Status      SchemaExtensionStatus        `json:"status,omitempty"`
}

type SchemaExtensionData struct {
	ID         string
	Properties SchemaExtensionProperties
}

func (se SchemaExtensionData) MarshalJSON() ([]byte, error) {
	in := map[string]interface{}{
		se.ID: se.Properties,
	}
	return json.Marshal(in)
}

type ScopedRoleMembership struct {
	AdministrativeUnitId *string   `json:"administrativeUnitId,omitempty"`
	Id                   *string   `json:"id,omitempty"`
	RoleId               *string   `json:"roleId,omitempty"`
	RoleMemberInfo       *Identity `json:"roleMemberInfo"`
}

// ServicePrincipal describes a Service Principal object.
type ServicePrincipal struct {
	DirectoryObject
	Owners                              *Owners                       `json:"owners@odata.bind,omitempty"`
	ClaimsMappingPolicies               *[]ClaimsMappingPolicy        `json:"claimsmappingpolicies@odata.bind,omitempty"`
	AccountEnabled                      *bool                         `json:"accountEnabled,omitempty"`
	AddIns                              *[]AddIn                      `json:"addIns,omitempty"`
	AlternativeNames                    *[]string                     `json:"alternativeNames,omitempty"`
	AppDisplayName                      *string                       `json:"appDisplayName,omitempty"`
	AppId                               *string                       `json:"appId,omitempty"`
	ApplicationTemplateId               *string                       `json:"applicationTemplateId,omitempty"`
	AppOwnerOrganizationId              *string                       `json:"appOwnerOrganizationId,omitempty"`
	AppRoleAssignmentRequired           *bool                         `json:"appRoleAssignmentRequired,omitempty"`
	AppRoles                            *[]AppRole                    `json:"appRoles,omitempty"`
	DeletedDateTime                     *time.Time                    `json:"deletedDateTime,omitempty"`
	Description                         *StringNullWhenEmpty          `json:"description,omitempty"`
	DisplayName                         *string                       `json:"displayName,omitempty"`
	Homepage                            *string                       `json:"homepage,omitempty"`
	Info                                *InformationalUrl             `json:"info,omitempty"`
	KeyCredentials                      *[]KeyCredential              `json:"keyCredentials,omitempty"`
	LoginUrl                            *StringNullWhenEmpty          `json:"loginUrl,omitempty"`
	LogoutUrl                           *string                       `json:"logoutUrl,omitempty"`
	Notes                               *StringNullWhenEmpty          `json:"notes,omitempty"`
	NotificationEmailAddresses          *[]string                     `json:"notificationEmailAddresses,omitempty"`
	PasswordCredentials                 *[]PasswordCredential         `json:"passwordCredentials,omitempty"`
	PasswordSingleSignOnSettings        *PasswordSingleSignOnSettings `json:"passwordSingleSignOnSettings,omitempty"`
	PreferredSingleSignOnMode           *PreferredSingleSignOnMode    `json:"preferredSingleSignOnMode,omitempty"`
	PreferredTokenSigningKeyEndDateTime *time.Time                    `json:"preferredTokenSigningKeyEndDateTime,omitempty"`
	PublishedPermissionScopes           *[]PermissionScope            `json:"publishedPermissionScopes,omitempty"`
	ReplyUrls                           *[]string                     `json:"replyUrls,omitempty"`
	SamlMetadataUrl                     *StringNullWhenEmpty          `json:"samlMetadataUrl,omitempty"`
	SamlSingleSignOnSettings            *SamlSingleSignOnSettings     `json:"samlSingleSignOnSettings,omitempty"`
	ServicePrincipalNames               *[]string                     `json:"servicePrincipalNames,omitempty"`
	ServicePrincipalType                *string                       `json:"servicePrincipalType,omitempty"`
	SignInAudience                      *SignInAudience               `json:"signInAudience,omitempty"`
	Tags                                *[]string                     `json:"tags,omitempty"`
	TokenEncryptionKeyId                *string                       `json:"tokenEncryptionKeyId,omitempty"`
	VerifiedPublisher                   *VerifiedPublisher            `json:"verifiedPublisher,omitempty"`
}

func (s *ServicePrincipal) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type serviceprincipal ServicePrincipal
	s2 := (*serviceprincipal)(s)
	if err := json.Unmarshal(data, s2); err != nil {
		return err
	}
	return nil
}

type SignInActivity struct {
	LastSignInDateTime  *time.Time `json:"lastSignInDateTime,omitempty"`
	LastSignInRequestId *string    `json:"lastSignInRequestId,omitempty"`
}

type SignInFrequencySessionControl struct {
	IsEnabled *bool   `json:"isEnabled,omitempty"`
	Type      *string `json:"type,omitempty"`
	Value     *int32  `json:"value,omitempty"`
}

type SignInReport struct {
	Id                               *string                           `json:"id,omitempty"`
	CreatedDateTime                  *time.Time                        `json:"createdDateTime,omitempty"`
	UserDisplayName                  *string                           `json:"userDisplayName,omitempty"`
	UserPrincipalName                *string                           `json:"userPrincipalName,omitempty"`
	UserId                           *string                           `json:"userId,omitempty"`
	AppId                            *string                           `json:"appId,omitempty"`
	AppDisplayName                   *string                           `json:"appDisplayName,omitempty"`
	IPAddress                        *string                           `json:"ipAddress,omitempty"`
	ClientAppUsed                    *string                           `json:"clientAppUsed,omitempty"`
	CorrelationId                    *string                           `json:"correlationId,omitempty"`
	ConditionalAccessStatus          *string                           `json:"conditionalAccessStatus,omitempty"`
	IsInteractive                    *bool                             `json:"isInteractive,omitempty"`
	RiskDetail                       *string                           `json:"riskDetail,omitempty"`
	RiskLevelAggregated              *string                           `json:"riskLevelAggregated,omitempty"`
	RiskLevelDuringSignIn            *string                           `json:"riskLevelDuringSignIn,omitempty"`
	RiskState                        *string                           `json:"riskState,omitempty"`
	RiskEventTypes                   *[]string                         `json:"riskEventTypes,omitempty"`
	ResourceDisplayName              *string                           `json:"resourceDisplayName,omitempty"`
	ResourceId                       *string                           `json:"resourceId,omitempty"`
	Status                           *Status                           `json:"status,omitempty"`
	DeviceDetail                     *DeviceDetail                     `json:"deviceDetail,omitempty"`
	Location                         *Location                         `json:"location,omitempty"`
	AppliedConditionalAccessPolicies *[]AppliedConditionalAccessPolicy `json:"appliedConditionalAccessPolicies,omitempty"`
}

type SingleSignOnField struct {
	CustomizedLabel *string `json:"customizedLabel,omitempty"`
	DefaultLabel    *string `json:"defaultLabel,omitempty"`
	FieldId         *string `json:"fieldId,omitempty"`
	Type            *string `json:"type,omitempty"`
}

type Status struct {
	ErrorCode         *int32  `json:"errorCode,omitempty"`
	FailureReason     *string `json:"failureReason,omitempty"`
	AdditionalDetails *string `json:"additionalDetails,omitempty"`
}

type TargetResource struct {
	Id                 *string             `json:"id,omitempty"`
	DisplayName        *string             `json:"displayName,omitempty"`
	Type               *string             `json:"type,omitempty"`
	UserPrincipalName  *string             `json:"userPrincipalName,omitempty"`
	GroupType          *string             `json:"groupType,omitempty"`
	ModifiedProperties *[]ModifiedProperty `json:"modifiedProperties,omitempty"`
}

type TemporaryAccessPassAuthenticationMethod struct {
	ID                    *string                `json:"id,omitempty"`
	TemporaryAccessPass   *string                `json:"temporaryAccessPass,omitempty"`
	CreatedDateTime       *time.Time             `json:"createdDateTime,omitempty"`
	StartDateTime         *time.Time             `json:"startDateTime,omitempty"`
	LifetimeInMinutes     *int32                 `json:"lifetimeInMinutes,omitempty"`
	IsUsableOnce          *bool                  `json:"isUsableOnce,omitempty"`
	IsUsable              *bool                  `json:"isUsable,omitempty"`
	MethodUsabilityReason *MethodUsabilityReason `json:"methodUsabilityReason,omitempty"`
}

type UnifiedRoleAssignment struct {
	DirectoryObject

	AppScopeId       *string `json:"appScopeId,omitempty"`
	DirectoryScopeId *string `json:"directoryScopeId,omitempty"`
	PrincipalId      *string `json:"principalId,omitempty"`
	RoleDefinitionId *string `json:"roleDefinitionId,omitempty"`
}

type UnifiedRoleDefinition struct {
	DirectoryObject

	Description     *StringNullWhenEmpty     `json:"description,omitempty"`
	DisplayName     *string                  `json:"displayName,omitempty"`
	IsBuiltIn       *bool                    `json:"isBuiltIn,omitempty"`
	IsEnabled       *bool                    `json:"isEnabled,omitempty"`
	ResourceScopes  *[]string                `json:"resourceScopes,omitempty"`
	RolePermissions *[]UnifiedRolePermission `json:"rolePermissions,omitempty"`
	TemplateId      *string                  `json:"templateId,omitempty"`
	Version         *string                  `json:"version,omitempty"`
}

type UnifiedRolePermission struct {
	AllowedResourceActions  *[]string            `json:"allowedResourceActions,omitempty"`
	Condition               *StringNullWhenEmpty `json:"condition,omitempty"`
	ExcludedResourceActions *[]string            `json:"excludedResourceActions,omitempty"`
}

// User describes a User object.
type User struct {
	DirectoryObject

	AboutMe                         *string                  `json:"aboutMe,omitempty"`
	AccountEnabled                  *bool                    `json:"accountEnabled,omitempty"`
	AgeGroup                        *AgeGroup                `json:"ageGroup,omitempty"`
	BusinessPhones                  *[]string                `json:"businessPhones,omitempty"`
	City                            *StringNullWhenEmpty     `json:"city,omitempty"`
	CompanyName                     *StringNullWhenEmpty     `json:"companyName,omitempty"`
	ConsentProvidedForMinor         *ConsentProvidedForMinor `json:"consentProvidedForMinor,omitempty"`
	Country                         *StringNullWhenEmpty     `json:"country,omitempty"`
	CreatedDateTime                 *time.Time               `json:"createdDateTime,omitempty"`
	CreationType                    *string                  `json:"creationType,omitempty"`
	DeletedDateTime                 *time.Time               `json:"deletedDateTime,omitempty"`
	Department                      *StringNullWhenEmpty     `json:"department,omitempty"`
	DisplayName                     *string                  `json:"displayName,omitempty"`
	EmployeeHireDate                *time.Time               `json:"employeeHireDate,omitempty"`
	EmployeeId                      *StringNullWhenEmpty     `json:"employeeId,omitempty"`
	EmployeeOrgData                 *EmployeeOrgData         `json:"employeeOrgData,omitempty"`
	EmployeeType                    *StringNullWhenEmpty     `json:"employeeType,omitempty"`
	ExternalUserState               *string                  `json:"externalUserState,omitempty"`
	FaxNumber                       *StringNullWhenEmpty     `json:"faxNumber,omitempty"`
	GivenName                       *StringNullWhenEmpty     `json:"givenName,omitempty"`
	ImAddresses                     *[]string                `json:"imAddresses,omitempty"`
	Interests                       *[]string                `json:"interests,omitempty"`
	IsManagementRestricted          *bool                    `json:"isManagementRestricted,omitempty"`
	IsResourceAccount               *bool                    `json:"isResourceAccount,omitempty"`
	JobTitle                        *StringNullWhenEmpty     `json:"jobTitle,omitempty"`
	Mail                            *StringNullWhenEmpty     `json:"mail,omitempty"`
	MailNickname                    *string                  `json:"mailNickname,omitempty"`
	MemberOf                        *[]DirectoryObject       `json:"memberOf,omitempty"`
	MobilePhone                     *StringNullWhenEmpty     `json:"mobilePhone,omitempty"`
	MySite                          *string                  `json:"mySite,omitempty"`
	OfficeLocation                  *StringNullWhenEmpty     `json:"officeLocation,omitempty"`
	OnPremisesDistinguishedName     *string                  `json:"onPremisesDistinguishedName,omitempty"`
	OnPremisesDomainName            *string                  `json:"onPremisesDomainName,omitempty"`
	OnPremisesImmutableId           *string                  `json:"onPremisesImmutableId,omitempty"`
	OnPremisesLastSyncDateTime      *string                  `json:"onPremisesLastSyncDateTime,omitempty"`
	OnPremisesSamAccountName        *string                  `json:"onPremisesSamAccountName,omitempty"`
	OnPremisesSecurityIdentifier    *string                  `json:"onPremisesSecurityIdentifier,omitempty"`
	OnPremisesSyncEnabled           *bool                    `json:"onPremisesSyncEnabled,omitempty"`
	OnPremisesUserPrincipalName     *string                  `json:"onPremisesUserPrincipalName,omitempty"`
	OtherMails                      *[]string                `json:"otherMails,omitempty"`
	PasswordPolicies                *StringNullWhenEmpty     `json:"passwordPolicies,omitempty"`
	PasswordProfile                 *UserPasswordProfile     `json:"passwordProfile,omitempty"`
	PastProjects                    *[]string                `json:"pastProjects,omitempty"`
	PostalCode                      *StringNullWhenEmpty     `json:"postalCode,omitempty"`
	PreferredDataLocation           *string                  `json:"preferredDataLocation,omitempty"`
	PreferredLanguage               *StringNullWhenEmpty     `json:"preferredLanguage,omitempty"`
	PreferredName                   *string                  `json:"preferredName,omitempty"`
	ProxyAddresses                  *[]string                `json:"proxyAddresses,omitempty"`
	RefreshTokensValidFromDateTime  *time.Time               `json:"refreshTokensValidFromDateTime,omitempty"`
	Responsibilities                *[]string                `json:"responsibilities,omitempty"`
	Schools                         *[]string                `json:"schools,omitempty"`
	ShowInAddressList               *bool                    `json:"showInAddressList,omitempty"`
	SignInActivity                  *SignInActivity          `json:"signInActivity,omitempty"`
	SignInSessionsValidFromDateTime *time.Time               `json:"signInSessionsValidFromDateTime,omitempty"`
	Skills                          *[]string                `json:"skills,omitempty"`
	State                           *StringNullWhenEmpty     `json:"state,omitempty"`
	StreetAddress                   *StringNullWhenEmpty     `json:"streetAddress,omitempty"`
	Surname                         *StringNullWhenEmpty     `json:"surname,omitempty"`
	UsageLocation                   *StringNullWhenEmpty     `json:"usageLocation,omitempty"`
	UserPrincipalName               *string                  `json:"userPrincipalName,omitempty"`
	UserType                        *string                  `json:"userType,omitempty"`

	SchemaExtensions *[]SchemaExtensionData `json:"-"`
}

func (u User) MarshalJSON() ([]byte, error) {
	docs := make([][]byte, 0)
	// Local type needed to avoid recursive MarshalJSON calls
	type user User
	d, err := json.Marshal(user(u))
	if err != nil {
		return d, err
	}
	docs = append(docs, d)
	if u.SchemaExtensions != nil {
		for _, se := range *u.SchemaExtensions {
			d, err := json.Marshal(se)
			if err != nil {
				return d, err
			}
			docs = append(docs, d)
		}
	}
	return MarshalDocs(docs)
}

func (u *User) UnmarshalJSON(data []byte) error {
	// Local type needed to avoid recursive UnmarshalJSON calls
	type user User
	u2 := (*user)(u)
	if err := json.Unmarshal(data, u2); err != nil {
		return err
	}
	if u.SchemaExtensions != nil {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for _, ext := range *u.SchemaExtensions {
			if v, ok := fields[ext.ID]; ok {
				if err := json.Unmarshal(v, &ext.Properties); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type UserIdentity struct {
	DisplayName       *string `json:"displayName,omitempty"`
	Id                *string `json:"id,omitempty"`
	IPAddress         *string `json:"ipAddress,omitempty"`
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
}

type UserPasswordProfile struct {
	ForceChangePasswordNextSignIn        *bool   `json:"forceChangePasswordNextSignIn,omitempty"`
	ForceChangePasswordNextSignInWithMfa *bool   `json:"forceChangePasswordNextSignInWithMfa,omitempty"`
	Password                             *string `json:"password,omitempty"`
}

type UserRegistrationCount struct {
	RegistrationStatus *RegistrationStatus `json:"registrationStatus,omitempty"`
	RegistrationCount  *int64              `json:"registrationCount,omitempty"`
}

type UserRegistrationFeatureCount struct {
	Feature   *AuthenticationMethodFeature `json:"feature,omitempty"`
	UserCount *int64                       `json:"userCount"`
}
type UserRegistrationFeatureSummary struct {
	TotalUserCount                *int64                          `json:"totalUserCount,omitempty"`
	UserRegistrationFeatureCounts *[]UserRegistrationFeatureCount `json:"userRegistrationFeatureCounts"`
	UserRoles                     IncludedUserRoles               `json:"userRoles,omitempty"`
	UserTypes                     IncludedUserTypes               `json:"userTypes,omitempty"`
}

type UserRegistrationMethodCount struct {
	AuthenticationMethod *string `json:"authenticationMethod,omitempty"`
	UserCount            *int64  `json:"userCount,omitempty"`
}

type UserRegistrationMethodSummary struct {
	TotalUserCount               *int64                         `json:"totalUserCount"`
	UserRegistrationMethodsCount *[]UserRegistrationMethodCount `json:"userRegistrationMethodCounts,omitempty"`
	UerRoles                     IncludedUserRoles              `json:"userRoles,omitempty"`
	UserTypes                    IncludedUserTypes              `json:"userTypes,omitempty"`
}

type UserSet struct {
	ODataType    *odata.Type `json:"@odata.type,omitempty"`
	IsBackup     *bool       `json:"isBackup,omitempty"`
	ID           *string     `json:"id,omitempty"` // Either user or group ID
	Description  *string     `json:"description,omitempty"`
	ManagerLevel *int32      `json:"managerLevel,omitempty"`
}

type UserCredentialUsageDetails struct {
	AuthMethod        *UsageAuthMethod `json:"authMethod,omitempty"`
	EventDateTime     *time.Time       `json:"eventDateTime,omitempty"`
	FailureReason     *string          `json:"failureReason,omitempty"`
	Feature           *FeatureType     `json:"feature,omitempty"`
	ID                *string          `json:"id,omitempty"`
	IsSuccess         *bool            `json:"isSuccess,omitempty"`
	UserDisplayName   *string          `json:"userDisplayName,omitempty"`
	UserPrincipalName *string          `json:"userPrincipalName,omitempty"`
}
type VerifiedPublisher struct {
	AddedDateTime       *time.Time `json:"addedDateTime,omitempty"`
	DisplayName         *string    `json:"displayName,omitempty"`
	VerifiedPublisherId *string    `json:"verifiedPublisherId,omitempty"`
}

type WindowsHelloForBusinessAuthenticationMethod struct {
	CreatedDateTime *time.Time                       `json:"createdDateTime,omitempty"`
	DisplayName     *string                          `json:"displayName,omitempty"`
	ID              *string                          `json:"id,omitempty"`
	KeyStrength     *AuthenticationMethodKeyStrength `json:"authenticationMethodKeyStrength,omitempty"`
}

type EmployeeOrgData struct {
	CostCenter *string `json:"costCenter,omitempty"`
	Division   *string `json:"division,omitempty"`
}

type Entity = DirectoryObject

type DeviceCompliancePolicy interface {
	GetPolicyBase() *DeviceCompliancePolicyBase
}

type DeviceCompliancePolicyBase struct {
	Entity

	CreatedDateTime      *time.Time `json:"createdDateTime,omitempty"`
	Description          *string    `json:"description,omitempty"`
	DisplayName          *string    `json:"displayName,omitempty"`
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	RoleScopeTagIds      *[]string  `json:"roleScopeTagIds,omitempty"`
	Version              *int32     `json:"version,omitempty"`

	ScheduledActionsForRule *[]DeviceManagementComplianceScheduledActionForRule `json:"scheduledActionsForRule,omitempty"`
}

type Windows10DeviceCompliancePolicy struct {
	DeviceCompliancePolicyBase
	ActiveFirewallRequired                      *bool                          `json:"activeFirewallRequired,omitempty"`
	AntiSpywareRequired                         *bool                          `json:"antiSpywareRequired,omitempty"`
	AntivirusRequired                           *bool                          `json:"antivirusRequired,omitempty"`
	BitLockerEnabled                            *bool                          `json:"bitLockerEnabled,omitempty"`
	CodeIntegrityEnabled                        *bool                          `json:"codeIntegrityEnabled,omitempty"`
	ConfigurationManagerComplianceRequired      *bool                          `json:"configurationManagerComplianceRequired,omitempty"`
	DefenderEnabled                             *bool                          `json:"defenderEnabled,omitempty"`
	DefenderVersion                             *string                        `json:"defenderVersion,omitempty"`
	DeviceCompliancePolicyScript                *DeviceCompliancePolicyScript  `json:"deviceCompliancePolicyScript,omitempty"`
	DeviceThreatProtectionEnabled               *bool                          `json:"deviceThreatProtectionEnabled,omitempty"`
	DeviceThreatProtectionRequiredSecurityLevel *DeviceThreatProtectionLevel   `json:"deviceThreatProtectionRequiredSecurityLevel,omitempty"`
	EarlyLaunchAntiMalwareDriverEnabled         *bool                          `json:"earlyLaunchAntiMalwareDriverEnabled,omitempty"`
	MobileOsMaximumVersion                      *string                        `json:"mobileOsMaximumVersion,omitempty"`
	MobileOsMinimumVersion                      *string                        `json:"mobileOsMinimumVersion,omitempty"`
	OsMaximumVersion                            *string                        `json:"osMaximumVersion,omitempty"`
	OsMinimumVersion                            *string                        `json:"osMinimumVersion,omitempty"`
	PasswordBlockSimple                         *bool                          `json:"passwordBlockSimple,omitempty"`
	PasswordExpirationDays                      *int32                         `json:"passwordExpirationDays,omitempty"`
	PasswordMinimumCharacterSetCount            *int32                         `json:"passwordMinimumCharacterSetCount,omitempty"`
	PasswordMinimumLength                       *int32                         `json:"passwordMinimumLength,omitempty"`
	PasswordMinutesOfInactivityBeforeLock       *int32                         `json:"passwordMinutesOfInactivityBeforeLock,omitempty"`
	PasswordPreviousPasswordBlockCount          *int32                         `json:"passwordPreviousPasswordBlockCount,omitempty"`
	PasswordRequired                            *bool                          `json:"passwordRequired,omitempty"`
	PasswordRequiredToUnlockFromIdle            *bool                          `json:"passwordRequiredToUnlockFromIdle,omitempty"`
	PasswordRequiredType                        *RequiredPasswordType          `json:"passwordRequiredType,omitempty"`
	RequireHealthyDeviceReport                  *bool                          `json:"requireHealthyDeviceReport,omitempty"`
	RtpEnabled                                  *bool                          `json:"rtpEnabled,omitempty"`
	SecureBootEnabled                           *bool                          `json:"secureBootEnabled,omitempty"`
	SignatureOutOfDate                          *bool                          `json:"signatureOutOfDate,omitempty"`
	StorageRequireEncryption                    *bool                          `json:"storageRequireEncryption,omitempty"`
	TpmRequired                                 *bool                          `json:"tpmRequired,omitempty"`
	ValidOperatingSystemBuildRanges             *[]OperatingSystemVersionRange `json:"validOperatingSystemBuildRanges,omitempty"`
}

func (a Windows10DeviceCompliancePolicy) GetPolicyBase() *DeviceCompliancePolicyBase {
	return &a.DeviceCompliancePolicyBase
}

type OperatingSystemVersionRange struct {
	Description    *string `json:"description,omitempty"`
	HighestVersion *string `json:"highestVersion,omitempty"`
	LowestVersion  *string `json:"lowestVersion,omitempty"`
}

type DeviceCompliancePolicyScript struct {
	DeviceComplianceScriptId *string `json:"deviceComplianceScriptId,omitempty"`
	RulesContent             *[]byte `json:"rulesContent,omitempty"`
}

type DeviceManagementConfigurationPolicy struct {
	Entity

	CreatedDateTime      *time.Time                                            `json:"createdDateTime,omitempty"`
	CreationSource       *string                                               `json:"creationSource,omitempty"`
	Description          *string                                               `json:"description,omitempty"`
	IsAssigned           *bool                                                 `json:"isAssigned,omitempty"`
	LastModifiedDateTime *time.Time                                            `json:"lastModifiedDateTime,omitempty"`
	Name                 *string                                               `json:"name,omitempty"`
	Platforms            *DeviceManagementConfigurationPlatforms               `json:"platforms,omitempty"`
	RoleScopeTagIds      *[]string                                             `json:"roleScopeTagIds,omitempty"`
	SettingCount         *int32                                                `json:"settingCount,omitempty"`
	Technologies         *DeviceManagementConfigurationTechnologies            `json:"technologies,omitempty"`
	TemplateReference    *DeviceManagementConfigurationPolicyTemplateReference `json:"templateReference,omitempty"`
}

type DeviceManagementConfigurationPolicyTemplateReference struct {
	TemplateDisplayName    *string                                      `json:"templateDisplayName,omitempty"`
	TemplateDisplayVersion *string                                      `json:"templateDisplayVersion,omitempty"`
	TemplateFamily         *DeviceManagementConfigurationTemplateFamily `json:"templateFamily,omitempty"`
	TemplateId             *string                                      `json:"templateId,omitempty"`
}

type IOSDeviceCompliancePolicy struct {
	DeviceCompliancePolicyBase
	AdvancedThreatProtectionRequiredSecurityLevel  *DeviceThreatProtectionLevel `json:"advancedThreatProtectionRequiredSecurityLevel,omitempty"`
	DeviceThreatProtectionEnabled                  *bool                        `json:"deviceThreatProtectionEnabled,omitempty"`
	DeviceThreatProtectionRequiredSecurityLevel    *DeviceThreatProtectionLevel `json:"deviceThreatProtectionRequiredSecurityLevel,omitempty"`
	ManagedEmailProfileRequired                    *bool                        `json:"managedEmailProfileRequired,omitempty"`
	OsMaximumBuildVersion                          *string                      `json:"osMaximumBuildVersion,omitempty"`
	OsMaximumVersion                               *string                      `json:"osMaximumVersion,omitempty"`
	OsMinimumBuildVersion                          *string                      `json:"osMinimumBuildVersion,omitempty"`
	OsMinimumVersion                               *string                      `json:"osMinimumVersion,omitempty"`
	PasscodeBlockSimple                            *bool                        `json:"passcodeBlockSimple,omitempty"`
	PasscodeExpirationDays                         *int32                       `json:"passcodeExpirationDays,omitempty"`
	PasscodeMinimumCharacterSetCount               *int32                       `json:"passcodeMinimumCharacterSetCount,omitempty"`
	PasscodeMinimumLength                          *int32                       `json:"passcodeMinimumLength,omitempty"`
	PasscodeMinutesOfInactivityBeforeLock          *int32                       `json:"passcodeMinutesOfInactivityBeforeLock,omitempty"`
	PasscodeMinutesOfInactivityBeforeScreenTimeout *int32                       `json:"passcodeMinutesOfInactivityBeforeScreenTimeout,omitempty"`
	PasscodePreviousPasscodeBlockCount             *int32                       `json:"passcodePreviousPasscodeBlockCount,omitempty"`
	PasscodeRequired                               *bool                        `json:"passcodeRequired,omitempty"`
	PasscodeRequiredType                           *RequiredPasswordType        `json:"passcodeRequiredType,omitempty"`
	RestrictedApps                                 *[]AppListItem               `json:"restrictedApps,omitempty"`
	SecurityBlockJailbrokenDevices                 *bool                        `json:"securityBlockJailbrokenDevices,omitempty"`
}

func (a IOSDeviceCompliancePolicy) GetPolicyBase() *DeviceCompliancePolicyBase {
	return &a.DeviceCompliancePolicyBase
}

type AppListItem struct {
	AppId       *string `json:"appId,omitempty"`
	AppStoreUrl *string `json:"appStoreUrl,omitempty"`
	Name        *string `json:"name,omitempty"`
	Publisher   *string `json:"publisher,omitempty"`
}

type DeviceAndAppManagementAssignmentTarget interface{}

type DeviceAndAppManagementAssignmentTargetBase struct {
	ODataType                                  *odata.Type `json:"@odata.type,omitempty"`
	DeviceAndAppManagementAssignmentFilterId   *string     `json:"deviceAndAppManagementAssignmentFilterId,omitempty"`
	DeviceAndAppManagementAssignmentFilterType *string     `json:"deviceAndAppManagementAssignmentFilterType,omitempty"`
}

type DeviceAndAppManagementAssignmentTargetAllDevices struct {
	DeviceAndAppManagementAssignmentTargetBase
}

type DeviceAndAppManagementAssignmentTargetAllLicensedUsers struct {
	DeviceAndAppManagementAssignmentTargetBase
}

type DeviceAndAppManagementAssignmentConfigurationManagerCollectionAssignmentTarget struct {
	DeviceAndAppManagementAssignmentTargetBase
	CollectionID *string `json:"collectionId,omitempty"`
}

type DeviceAndAppManagementAssignmentGroupAssignmentTarget struct {
	DeviceAndAppManagementAssignmentTargetBase
	GroupID *string `json:"groupId,omitempty"`
}

type DeviceCompliancePolicyAssignment struct {
	Entity

	Source   *DeviceAndAppManagementAssignmentSource `json:"source,omitempty"`
	SourceId *string                                 `json:"sourceId,omitempty"`
	Target   DeviceAndAppManagementAssignmentTarget  `json:"target,omitempty"`
}

type DeviceManagementComplianceScheduledActionForRule struct {
	Entity

	RuleName                      *string                       `json:"ruleName,omitempty"`
	ScheduledActionConfigurations *[]DeviceComplianceActionItem `json:"scheduledActionConfigurations,omitempty"`
}

type DeviceComplianceActionItem struct {
	Entity

	ActionType                *DeviceComplianceActionType `json:"actionType,omitempty"`
	GracePeriodHours          *int32                      `json:"gracePeriodHours,omitempty"`
	NotificationMessageCCList *[]string                   `json:"notificationMessageCCList,omitempty"`
	NotificationTemplateId    *string                     `json:"notificationTemplateId,omitempty"`
}

type ManagedDevice struct {
	Entity

	CloudPcRemoteActionResults                *[]CloudPcRemoteActionResult               `json:"cloudPcRemoteActionResults,omitempty"`
	AadRegistered                             *bool                                      `json:"aadRegistered,omitempty"`
	ActivationLockBypassCode                  *string                                    `json:"activationLockBypassCode,omitempty"`
	AndroidSecurityPatchLevel                 *string                                    `json:"androidSecurityPatchLevel,omitempty"`
	AutopilotEnrolled                         *bool                                      `json:"autopilotEnrolled,omitempty"`
	AzureActiveDirectoryDeviceId              *string                                    `json:"azureActiveDirectoryDeviceId,omitempty"`
	AzureADDeviceId                           *string                                    `json:"azureADDeviceId,omitempty"`
	AzureADRegistered                         *bool                                      `json:"azureADRegistered,omitempty"`
	ChassisType                               *ChassisType                               `json:"chassisType,omitempty"`
	ChromeOSDeviceInfo                        *[]ChromeOSDeviceProperty                  `json:"chromeOSDeviceInfo,omitempty"`
	ComplianceGracePeriodExpirationDateTime   *time.Time                                 `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	ComplianceState                           *ComplianceState                           `json:"complianceState,omitempty"`
	ConfigurationManagerClientEnabledFeatures *ConfigurationManagerClientEnabledFeatures `json:"configurationManagerClientEnabledFeatures,omitempty"`
	ConfigurationManagerClientHealthState     *ConfigurationManagerClientHealthState     `json:"configurationManagerClientHealthState,omitempty"`
	ConfigurationManagerClientInformation     *ConfigurationManagerClientInformation     `json:"configurationManagerClientInformation,omitempty"`
	DeviceActionResults                       *[]DeviceActionResult                      `json:"deviceActionResults,omitempty"`
	DeviceCategoryDisplayName                 *string                                    `json:"deviceCategoryDisplayName,omitempty"`
	DeviceEnrollmentType                      *DeviceEnrollmentType                      `json:"deviceEnrollmentType,omitempty"`
	DeviceHealthAttestationState              *DeviceHealthAttestationState              `json:"deviceHealthAttestationState,omitempty"`
	DeviceName                                *string                                    `json:"deviceName,omitempty"`
	DeviceRegistrationState                   *DeviceRegistrationState                   `json:"deviceRegistrationState,omitempty"`
	DeviceType                                *DeviceType                                `json:"deviceType,omitempty"`
	EasActivated                              *bool                                      `json:"easActivated,omitempty"`
	EasActivationDateTime                     *time.Time                                 `json:"easActivationDateTime,omitempty"`
	EasDeviceId                               *string                                    `json:"easDeviceId,omitempty"`
	EmailAddress                              *string                                    `json:"emailAddress,omitempty"`
	EnrolledDateTime                          *time.Time                                 `json:"enrolledDateTime,omitempty"`
	EnrollmentProfileName                     *string                                    `json:"enrollmentProfileName,omitempty"`
	EthernetMacAddress                        *string                                    `json:"ethernetMacAddress,omitempty"`
	ExchangeAccessState                       *DeviceManagementExchangeAccessState       `json:"exchangeAccessState,omitempty"`
	ExchangeAccessStateReason                 *DeviceManagementExchangeAccessStateReason `json:"exchangeAccessStateReason,omitempty"`
	ExchangeLastSuccessfulSyncDateTime        *time.Time                                 `json:"exchangeLastSuccessfulSyncDateTime,omitempty"`
	FreeStorageSpaceInBytes                   *int64                                     `json:"freeStorageSpaceInBytes,omitempty"`
	HardwareInformation                       *HardwareInformation                       `json:"hardwareInformation,omitempty"`
	Iccid                                     *string                                    `json:"iccid,omitempty"`
	Imei                                      *string                                    `json:"imei,omitempty"`
	IsEncrypted                               *bool                                      `json:"isEncrypted,omitempty"`
	IsSupervised                              *bool                                      `json:"isSupervised,omitempty"`
	JailBroken                                *string                                    `json:"jailBroken,omitempty"`
	JoinType                                  *JoinType                                  `json:"joinType,omitempty"`
	LastSyncDateTime                          *time.Time                                 `json:"lastSyncDateTime,omitempty"`
	LostModeState                             *LostModeState                             `json:"lostModeState,omitempty"`
	ManagedDeviceName                         *string                                    `json:"managedDeviceName,omitempty"`
	ManagedDeviceOwnerType                    *ManagedDeviceOwnerType                    `json:"managedDeviceOwnerType,omitempty"`
	ManagementAgent                           *ManagementAgentType                       `json:"managementAgent,omitempty"`
	ManagementCertificateExpirationDate       *time.Time                                 `json:"managementCertificateExpirationDate,omitempty"`
	ManagementFeatures                        *ManagedDeviceManagementFeatures           `json:"managementFeatures,omitempty"`
	ManagementState                           *ManagementState                           `json:"managementState,omitempty"`
	Manufacturer                              *string                                    `json:"manufacturer,omitempty"`
	Meid                                      *string                                    `json:"meid,omitempty"`
	Model                                     *string                                    `json:"model,omitempty"`
	Notes                                     *string                                    `json:"notes,omitempty"`
	OperatingSystem                           *string                                    `json:"operatingSystem,omitempty"`
	OsVersion                                 *string                                    `json:"osVersion,omitempty"`
	OwnerType                                 *OwnerType                                 `json:"ownerType,omitempty"`
	PartnerReportedThreatState                *ManagedDevicePartnerReportedHealthState   `json:"partnerReportedThreatState,omitempty"`
	PhoneNumber                               *string                                    `json:"phoneNumber,omitempty"`
	PhysicalMemoryInBytes                     *int64                                     `json:"physicalMemoryInBytes,omitempty"`
	PreferMdmOverGroupPolicyAppliedDateTime   *time.Time                                 `json:"preferMdmOverGroupPolicyAppliedDateTime,omitempty"`
	ProcessorArchitecture                     *ManagedDeviceArchitecture                 `json:"processorArchitecture,omitempty"`
	RemoteAssistanceSessionErrorDetails       *string                                    `json:"remoteAssistanceSessionErrorDetails,omitempty"`
	RemoteAssistanceSessionUrl                *string                                    `json:"remoteAssistanceSessionUrl,omitempty"`
	RequireUserEnrollmentApproval             *bool                                      `json:"requireUserEnrollmentApproval,omitempty"`
	RetireAfterDateTime                       *time.Time                                 `json:"retireAfterDateTime,omitempty"`
	RoleScopeTagIds                           *[]string                                  `json:"roleScopeTagIds,omitempty"`
	SerialNumber                              *string                                    `json:"serialNumber,omitempty"`
	SkuFamily                                 *string                                    `json:"skuFamily,omitempty"`
	SkuNumber                                 *int32                                     `json:"skuNumber,omitempty"`
	SpecificationVersion                      *string                                    `json:"specificationVersion,omitempty"`
	SubscriberCarrier                         *string                                    `json:"subscriberCarrier,omitempty"`
	TotalStorageSpaceInBytes                  *int64                                     `json:"totalStorageSpaceInBytes,omitempty"`
	Udid                                      *string                                    `json:"udid,omitempty"`
	UserDisplayName                           *string                                    `json:"userDisplayName,omitempty"`
	UserId                                    *string                                    `json:"userId,omitempty"`
	UserPrincipalName                         *string                                    `json:"userPrincipalName,omitempty"`
	UsersLoggedOn                             *[]LoggedOnUser                            `json:"usersLoggedOn,omitempty"`
	WiFiMacAddress                            *string                                    `json:"wiFiMacAddress,omitempty"`
	WindowsActiveMalwareCount                 *int32                                     `json:"windowsActiveMalwareCount,omitempty"`
	WindowsRemediatedMalwareCount             *int32                                     `json:"windowsRemediatedMalwareCount,omitempty"`
}

type WindowsManagedDevice struct {
	ManagedDevice
}

type WindowsProtectionState struct {
	Entity

	AntiMalwareVersion             *string                       `json:"antiMalwareVersion,omitempty"`
	DeviceState                    *WindowsDeviceHealthState     `json:"deviceState,omitempty"`
	EngineVersion                  *string                       `json:"engineVersion,omitempty"`
	FullScanOverdue                *bool                         `json:"fullScanOverdue,omitempty"`
	FullScanRequired               *bool                         `json:"fullScanRequired,omitempty"`
	IsVirtualMachine               *bool                         `json:"isVirtualMachine,omitempty"`
	LastFullScanDateTime           *time.Time                    `json:"lastFullScanDateTime,omitempty"`
	LastFullScanSignatureVersion   *string                       `json:"lastFullScanSignatureVersion,omitempty"`
	LastQuickScanDateTime          *time.Time                    `json:"lastQuickScanDateTime,omitempty"`
	LastQuickScanSignatureVersion  *string                       `json:"lastQuickScanSignatureVersion,omitempty"`
	LastReportedDateTime           *time.Time                    `json:"lastReportedDateTime,omitempty"`
	MalwareProtectionEnabled       *bool                         `json:"malwareProtectionEnabled,omitempty"`
	NetworkInspectionSystemEnabled *bool                         `json:"networkInspectionSystemEnabled,omitempty"`
	ProductStatus                  *WindowsDefenderProductStatus `json:"productStatus,omitempty"`
	QuickScanOverdue               *bool                         `json:"quickScanOverdue,omitempty"`
	RealTimeProtectionEnabled      *bool                         `json:"realTimeProtectionEnabled,omitempty"`
	RebootRequired                 *bool                         `json:"rebootRequired,omitempty"`
	SignatureUpdateOverdue         *bool                         `json:"signatureUpdateOverdue,omitempty"`
	SignatureVersion               *string                       `json:"signatureVersion,omitempty"`
	TamperProtectionEnabled        *bool                         `json:"tamperProtectionEnabled,omitempty"`
}

type CloudPcRemoteActionResult struct {
	ActionName          *string               `json:"actionName,omitempty"`
	ActionState         *ActionState          `json:"actionState,omitempty"`
	CloudPcId           *string               `json:"cloudPcId,omitempty"`
	LastUpdatedDateTime *time.Time            `json:"lastUpdatedDateTime,omitempty"`
	ManagedDeviceId     *string               `json:"managedDeviceId,omitempty"`
	StartDateTime       *time.Time            `json:"startDateTime,omitempty"`
	StatusDetails       *CloudPcStatusDetails `json:"statusDetails,omitempty"`
}

type CloudPcStatusDetails struct {
	AdditionalInformation *[]KeyValuePair `json:"additionalInformation,omitempty"`
	Code                  *string         `json:"code,omitempty"`
	Message               *string         `json:"message,omitempty"`
}

type ChromeOSDeviceProperty struct {
	Name      *string `json:"name,omitempty"`
	Updatable *bool   `json:"updatable,omitempty"`
	Value     *string `json:"value,omitempty"`
	ValueType *string `json:"valueType,omitempty"`
}

type LoggedOnUser struct {
	LastLogOnDateTime *time.Time `json:"lastLogOnDateTime,omitempty"`
	UserId            *string    `json:"userId,omitempty"`
}

type ConfigurationManagerClientInformation struct {
	ClientIdentifier *string `json:"clientIdentifier,omitempty"`
	IsBlocked        *bool   `json:"isBlocked,omitempty"`
}

type ConfigurationManagerClientEnabledFeatures struct {
	CompliancePolicy         *bool `json:"compliancePolicy,omitempty"`
	DeviceConfiguration      *bool `json:"deviceConfiguration,omitempty"`
	EndpointProtection       *bool `json:"endpointProtection,omitempty"`
	Inventory                *bool `json:"inventory,omitempty"`
	ModernApps               *bool `json:"modernApps,omitempty"`
	OfficeApps               *bool `json:"officeApps,omitempty"`
	ResourceAccess           *bool `json:"resourceAccess,omitempty"`
	WindowsUpdateForBusiness *bool `json:"windowsUpdateForBusiness,omitempty"`
}

type KeyValuePair struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

type ConfigurationManagerClientHealthState struct {
	ErrorCode        *int32                           `json:"errorCode,omitempty"`
	LastSyncDateTime *time.Time                       `json:"lastSyncDateTime,omitempty"`
	State            *ConfigurationManagerClientState `json:"state,omitempty"`
}

type DeviceActionResult struct {
	ActionName          *string      `json:"actionName,omitempty"`
	ActionState         *ActionState `json:"actionState,omitempty"`
	LastUpdatedDateTime *time.Time   `json:"lastUpdatedDateTime,omitempty"`
	StartDateTime       *time.Time   `json:"startDateTime,omitempty"`
}

type DeviceHealthAttestationState struct {
	AttestationIdentityKey                   *string    `json:"attestationIdentityKey,omitempty"`
	BitLockerStatus                          *string    `json:"bitLockerStatus,omitempty"`
	BootAppSecurityVersion                   *string    `json:"bootAppSecurityVersion,omitempty"`
	BootDebugging                            *string    `json:"bootDebugging,omitempty"`
	BootManagerSecurityVersion               *string    `json:"bootManagerSecurityVersion,omitempty"`
	BootManagerVersion                       *string    `json:"bootManagerVersion,omitempty"`
	BootRevisionListInfo                     *string    `json:"bootRevisionListInfo,omitempty"`
	CodeIntegrity                            *string    `json:"codeIntegrity,omitempty"`
	CodeIntegrityCheckVersion                *string    `json:"codeIntegrityCheckVersion,omitempty"`
	CodeIntegrityPolicy                      *string    `json:"codeIntegrityPolicy,omitempty"`
	ContentNamespaceUrl                      *string    `json:"contentNamespaceUrl,omitempty"`
	ContentVersion                           *string    `json:"contentVersion,omitempty"`
	DataExcutionPolicy                       *string    `json:"dataExcutionPolicy,omitempty"`
	DeviceHealthAttestationStatus            *string    `json:"deviceHealthAttestationStatus,omitempty"`
	EarlyLaunchAntiMalwareDriverProtection   *string    `json:"earlyLaunchAntiMalwareDriverProtection,omitempty"`
	HealthAttestationSupportedStatus         *string    `json:"healthAttestationSupportedStatus,omitempty"`
	HealthStatusMismatchInfo                 *string    `json:"healthStatusMismatchInfo,omitempty"`
	IssuedDateTime                           *time.Time `json:"issuedDateTime,omitempty"`
	LastUpdateDateTime                       *string    `json:"lastUpdateDateTime,omitempty"`
	OperatingSystemKernelDebugging           *string    `json:"operatingSystemKernelDebugging,omitempty"`
	OperatingSystemRevListInfo               *string    `json:"operatingSystemRevListInfo,omitempty"`
	Pcr0                                     *string    `json:"pcr0,omitempty"`
	PcrHashAlgorithm                         *string    `json:"pcrHashAlgorithm,omitempty"`
	ResetCount                               *int64     `json:"resetCount,omitempty"`
	RestartCount                             *int64     `json:"restartCount,omitempty"`
	SafeMode                                 *string    `json:"safeMode,omitempty"`
	SecureBoot                               *string    `json:"secureBoot,omitempty"`
	SecureBootConfigurationPolicyFingerPrint *string    `json:"secureBootConfigurationPolicyFingerPrint,omitempty"`
	TestSigning                              *string    `json:"testSigning,omitempty"`
	TpmVersion                               *string    `json:"tpmVersion,omitempty"`
	VirtualSecureMode                        *string    `json:"virtualSecureMode,omitempty"`
	WindowsPE                                *string    `json:"windowsPE,omitempty"`
}

type HardwareInformation struct {
	BatteryChargeCycles                                            *int32                                                          `json:"batteryChargeCycles,omitempty"`
	BatteryHealthPercentage                                        *int32                                                          `json:"batteryHealthPercentage,omitempty"`
	BatterySerialNumber                                            *string                                                         `json:"batterySerialNumber,omitempty"`
	CellularTechnology                                             *string                                                         `json:"cellularTechnology,omitempty"`
	DeviceFullQualifiedDomainName                                  *string                                                         `json:"deviceFullQualifiedDomainName,omitempty"`
	DeviceGuardLocalSystemAuthorityCredentialGuardState            *DeviceGuardLocalSystemAuthorityCredentialGuardState            `json:"deviceGuardLocalSystemAuthorityCredentialGuardState,omitempty"`
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementState *DeviceGuardVirtualizationBasedSecurityHardwareRequirementState `json:"deviceGuardVirtualizationBasedSecurityHardwareRequirementState,omitempty"`
	DeviceGuardVirtualizationBasedSecurityState                    *DeviceGuardVirtualizationBasedSecurityState                    `json:"deviceGuardVirtualizationBasedSecurityState,omitempty"`
	EsimIdentifier                                                 *string                                                         `json:"esimIdentifier,omitempty"`
	FreeStorageSpace                                               *int64                                                          `json:"freeStorageSpace,omitempty"`
	Imei                                                           *string                                                         `json:"imei,omitempty"`
	IpAddressV4                                                    *string                                                         `json:"ipAddressV4,omitempty"`
	IsEncrypted                                                    *bool                                                           `json:"isEncrypted,omitempty"`
	IsSharedDevice                                                 *bool                                                           `json:"isSharedDevice,omitempty"`
	IsSupervised                                                   *bool                                                           `json:"isSupervised,omitempty"`
	Manufacturer                                                   *string                                                         `json:"manufacturer,omitempty"`
	Meid                                                           *string                                                         `json:"meid,omitempty"`
	Model                                                          *string                                                         `json:"model,omitempty"`
	OperatingSystemEdition                                         *string                                                         `json:"operatingSystemEdition,omitempty"`
	OperatingSystemLanguage                                        *string                                                         `json:"operatingSystemLanguage,omitempty"`
	OperatingSystemProductType                                     *int32                                                          `json:"operatingSystemProductType,omitempty"`
	OsBuildNumber                                                  *string                                                         `json:"osBuildNumber,omitempty"`
	PhoneNumber                                                    *string                                                         `json:"phoneNumber,omitempty"`
	SerialNumber                                                   *string                                                         `json:"serialNumber,omitempty"`
	SharedDeviceCachedUsers                                        *[]SharedAppleDeviceUser                                        `json:"sharedDeviceCachedUsers,omitempty"`
	SubnetAddress                                                  *string                                                         `json:"subnetAddress,omitempty"`
	SubscriberCarrier                                              *string                                                         `json:"subscriberCarrier,omitempty"`
	SystemManagementBIOSVersion                                    *string                                                         `json:"systemManagementBIOSVersion,omitempty"`
	TotalStorageSpace                                              *int64                                                          `json:"totalStorageSpace,omitempty"`
	TpmManufacturer                                                *string                                                         `json:"tpmManufacturer,omitempty"`
	TpmSpecificationVersion                                        *string                                                         `json:"tpmSpecificationVersion,omitempty"`
	TpmVersion                                                     *string                                                         `json:"tpmVersion,omitempty"`
	WifiMac                                                        *string                                                         `json:"wifiMac,omitempty"`
}

type SharedAppleDeviceUser struct {
	DataQuota         *int64  `json:"dataQuota,omitempty"`
	DataToSync        *bool   `json:"dataToSync,omitempty"`
	DataUsed          *int64  `json:"dataUsed,omitempty"`
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
}

type DeviceManagementApplicabilityRuleOsEdition struct {
	Name           *string                                `json:"name,omitempty"`
	OsEditionTypes *[]Windows10EditionType                `json:"osEditionTypes,omitempty"`
	RuleType       *DeviceManagementApplicabilityRuleType `json:"ruleType,omitempty"`
}

type EdgeHomeButtonConfiguration struct {
}

type DeviceConfiguration interface {
	GetConfigurationBase() *DeviceConfigurationBase
}

type DeviceConfigurationBase struct {
	Entity

	CreatedDateTime                             *time.Time                                   `json:"createdDateTime,omitempty"`
	Description                                 *string                                      `json:"description,omitempty"`
	DeviceManagementApplicabilityRuleDeviceMode *DeviceManagementApplicabilityRuleDeviceMode `json:"deviceManagementApplicabilityRuleDeviceMode,omitempty"`
	DeviceManagementApplicabilityRuleOsEdition  *DeviceManagementApplicabilityRuleOsEdition  `json:"deviceManagementApplicabilityRuleOsEdition,omitempty"`
	DeviceManagementApplicabilityRuleOsVersion  *DeviceManagementApplicabilityRuleOsVersion  `json:"deviceManagementApplicabilityRuleOsVersion,omitempty"`
	DisplayName                                 *string                                      `json:"displayName,omitempty"`
	LastModifiedDateTime                        *time.Time                                   `json:"lastModifiedDateTime,omitempty"`
	RoleScopeTagIds                             *[]string                                    `json:"roleScopeTagIds,omitempty"`
	SupportsScopeTags                           *bool                                        `json:"supportsScopeTags,omitempty"`
	Version                                     *int32                                       `json:"version,omitempty"`
}

type Windows10GeneralConfiguration struct {
	DeviceConfigurationBase

	AccountsBlockAddingNonMicrosoftAccountEmail           *bool                                  `json:"accountsBlockAddingNonMicrosoftAccountEmail,omitempty"`
	ActivateAppsWithVoice                                 *Enablement                            `json:"activateAppsWithVoice,omitempty"`
	AntiTheftModeBlocked                                  *bool                                  `json:"antiTheftModeBlocked,omitempty"`
	AppManagementMSIAllowUserControlOverInstall           *bool                                  `json:"appManagementMSIAllowUserControlOverInstall,omitempty"`
	AppManagementMSIAlwaysInstallWithElevatedPrivileges   *bool                                  `json:"appManagementMSIAlwaysInstallWithElevatedPrivileges,omitempty"`
	AppManagementPackageFamilyNamesToLaunchAfterLogOn     *[]string                              `json:"appManagementPackageFamilyNamesToLaunchAfterLogOn,omitempty"`
	AppsAllowTrustedAppsSideloading                       *StateManagementSetting                `json:"appsAllowTrustedAppsSideloading,omitempty"`
	AppsBlockWindowsStoreOriginatedApps                   *bool                                  `json:"appsBlockWindowsStoreOriginatedApps,omitempty"`
	AuthenticationAllowSecondaryDevice                    *bool                                  `json:"authenticationAllowSecondaryDevice,omitempty"`
	AuthenticationPreferredAzureADTenantDomainName        *string                                `json:"authenticationPreferredAzureADTenantDomainName,omitempty"`
	AuthenticationWebSignIn                               *Enablement                            `json:"authenticationWebSignIn,omitempty"`
	BluetoothAllowedServices                              *[]string                              `json:"bluetoothAllowedServices,omitempty"`
	BluetoothBlockAdvertising                             *bool                                  `json:"bluetoothBlockAdvertising,omitempty"`
	BluetoothBlockDiscoverableMode                        *bool                                  `json:"bluetoothBlockDiscoverableMode,omitempty"`
	BluetoothBlocked                                      *bool                                  `json:"bluetoothBlocked,omitempty"`
	BluetoothBlockPrePairing                              *bool                                  `json:"bluetoothBlockPrePairing,omitempty"`
	BluetoothBlockPromptedProximalConnections             *bool                                  `json:"bluetoothBlockPromptedProximalConnections,omitempty"`
	CameraBlocked                                         *bool                                  `json:"cameraBlocked,omitempty"`
	CellularBlockDataWhenRoaming                          *bool                                  `json:"cellularBlockDataWhenRoaming,omitempty"`
	CellularBlockVpn                                      *bool                                  `json:"cellularBlockVpn,omitempty"`
	CellularBlockVpnWhenRoaming                           *bool                                  `json:"cellularBlockVpnWhenRoaming,omitempty"`
	CellularData                                          *ConfigurationUsage                    `json:"cellularData,omitempty"`
	CertificatesBlockManualRootCertificateInstallation    *bool                                  `json:"certificatesBlockManualRootCertificateInstallation,omitempty"`
	ConfigureTimeZone                                     *string                                `json:"configureTimeZone,omitempty"`
	ConnectedDevicesServiceBlocked                        *bool                                  `json:"connectedDevicesServiceBlocked,omitempty"`
	CopyPasteBlocked                                      *bool                                  `json:"copyPasteBlocked,omitempty"`
	CortanaBlocked                                        *bool                                  `json:"cortanaBlocked,omitempty"`
	CryptographyAllowFipsAlgorithmPolicy                  *bool                                  `json:"cryptographyAllowFipsAlgorithmPolicy,omitempty"`
	DataProtectionBlockDirectMemoryAccess                 *bool                                  `json:"dataProtectionBlockDirectMemoryAccess,omitempty"`
	DefenderBlockEndUserAccess                            *bool                                  `json:"defenderBlockEndUserAccess,omitempty"`
	DefenderBlockOnAccessProtection                       *bool                                  `json:"defenderBlockOnAccessProtection,omitempty"`
	DefenderCloudBlockLevel                               *DefenderCloudBlockLevelType           `json:"defenderCloudBlockLevel,omitempty"`
	DefenderCloudExtendedTimeout                          *int32                                 `json:"defenderCloudExtendedTimeout,omitempty"`
	DefenderCloudExtendedTimeoutInSeconds                 *int32                                 `json:"defenderCloudExtendedTimeoutInSeconds,omitempty"`
	DefenderDaysBeforeDeletingQuarantinedMalware          *int32                                 `json:"defenderDaysBeforeDeletingQuarantinedMalware,omitempty"`
	DefenderDetectedMalwareActions                        *DefenderDetectedMalwareActions        `json:"defenderDetectedMalwareActions,omitempty"`
	DefenderDisableCatchupFullScan                        *bool                                  `json:"defenderDisableCatchupFullScan,omitempty"`
	DefenderDisableCatchupQuickScan                       *bool                                  `json:"defenderDisableCatchupQuickScan,omitempty"`
	DefenderFileExtensionsToExclude                       *[]string                              `json:"defenderFileExtensionsToExclude,omitempty"`
	DefenderFilesAndFoldersToExclude                      *[]string                              `json:"defenderFilesAndFoldersToExclude,omitempty"`
	DefenderMonitorFileActivity                           *DefenderMonitorFileActivity           `json:"defenderMonitorFileActivity,omitempty"`
	DefenderPotentiallyUnwantedAppAction                  *DefenderPotentiallyUnwantedAppAction  `json:"defenderPotentiallyUnwantedAppAction,omitempty"`
	DefenderPotentiallyUnwantedAppActionSetting           *DefenderProtectionType                `json:"defenderPotentiallyUnwantedAppActionSetting,omitempty"`
	DefenderProcessesToExclude                            *[]string                              `json:"defenderProcessesToExclude,omitempty"`
	DefenderPromptForSampleSubmission                     *DefenderPromptForSampleSubmission     `json:"defenderPromptForSampleSubmission,omitempty"`
	DefenderRequireBehaviorMonitoring                     *bool                                  `json:"defenderRequireBehaviorMonitoring,omitempty"`
	DefenderRequireCloudProtection                        *bool                                  `json:"defenderRequireCloudProtection,omitempty"`
	DefenderRequireNetworkInspectionSystem                *bool                                  `json:"defenderRequireNetworkInspectionSystem,omitempty"`
	DefenderRequireRealTimeMonitoring                     *bool                                  `json:"defenderRequireRealTimeMonitoring,omitempty"`
	DefenderScanArchiveFiles                              *bool                                  `json:"defenderScanArchiveFiles,omitempty"`
	DefenderScanDownloads                                 *bool                                  `json:"defenderScanDownloads,omitempty"`
	DefenderScanIncomingMail                              *bool                                  `json:"defenderScanIncomingMail,omitempty"`
	DefenderScanMappedNetworkDrivesDuringFullScan         *bool                                  `json:"defenderScanMappedNetworkDrivesDuringFullScan,omitempty"`
	DefenderScanMaxCpu                                    *int32                                 `json:"defenderScanMaxCpu,omitempty"`
	DefenderScanNetworkFiles                              *bool                                  `json:"defenderScanNetworkFiles,omitempty"`
	DefenderScanRemovableDrivesDuringFullScan             *bool                                  `json:"defenderScanRemovableDrivesDuringFullScan,omitempty"`
	DefenderScanScriptsLoadedInInternetExplorer           *bool                                  `json:"defenderScanScriptsLoadedInInternetExplorer,omitempty"`
	DefenderScanType                                      *DefenderScanType                      `json:"defenderScanType,omitempty"`
	DefenderScheduledQuickScanTime                        *time.Time                             `json:"defenderScheduledQuickScanTime,omitempty"`
	DefenderScheduledScanTime                             *time.Time                             `json:"defenderScheduledScanTime,omitempty"`
	DefenderScheduleScanEnableLowCpuPriority              *bool                                  `json:"defenderScheduleScanEnableLowCpuPriority,omitempty"`
	DefenderSignatureUpdateIntervalInHours                *int32                                 `json:"defenderSignatureUpdateIntervalInHours,omitempty"`
	DefenderSubmitSamplesConsentType                      *DefenderSubmitSamplesConsentType      `json:"defenderSubmitSamplesConsentType,omitempty"`
	DefenderSystemScanSchedule                            *WeeklySchedule                        `json:"defenderSystemScanSchedule,omitempty"`
	DeveloperUnlockSetting                                *StateManagementSetting                `json:"developerUnlockSetting,omitempty"`
	DeviceManagementBlockFactoryResetOnMobile             *bool                                  `json:"deviceManagementBlockFactoryResetOnMobile,omitempty"`
	DeviceManagementBlockManualUnenroll                   *bool                                  `json:"deviceManagementBlockManualUnenroll,omitempty"`
	DiagnosticsDataSubmissionMode                         *DiagnosticDataSubmissionMode          `json:"diagnosticsDataSubmissionMode,omitempty"`
	DisplayAppListWithGdiDPIScalingTurnedOff              *[]string                              `json:"displayAppListWithGdiDPIScalingTurnedOff,omitempty"`
	DisplayAppListWithGdiDPIScalingTurnedOn               *[]string                              `json:"displayAppListWithGdiDPIScalingTurnedOn,omitempty"`
	EdgeAllowStartPagesModification                       *bool                                  `json:"edgeAllowStartPagesModification,omitempty"`
	EdgeBlockAccessToAboutFlags                           *bool                                  `json:"edgeBlockAccessToAboutFlags,omitempty"`
	EdgeBlockAddressBarDropdown                           *bool                                  `json:"edgeBlockAddressBarDropdown,omitempty"`
	EdgeBlockAutofill                                     *bool                                  `json:"edgeBlockAutofill,omitempty"`
	EdgeBlockCompatibilityList                            *bool                                  `json:"edgeBlockCompatibilityList,omitempty"`
	EdgeBlockDeveloperTools                               *bool                                  `json:"edgeBlockDeveloperTools,omitempty"`
	EdgeBlocked                                           *bool                                  `json:"edgeBlocked,omitempty"`
	EdgeBlockEditFavorites                                *bool                                  `json:"edgeBlockEditFavorites,omitempty"`
	EdgeBlockExtensions                                   *bool                                  `json:"edgeBlockExtensions,omitempty"`
	EdgeBlockFullScreenMode                               *bool                                  `json:"edgeBlockFullScreenMode,omitempty"`
	EdgeBlockInPrivateBrowsing                            *bool                                  `json:"edgeBlockInPrivateBrowsing,omitempty"`
	EdgeBlockJavaScript                                   *bool                                  `json:"edgeBlockJavaScript,omitempty"`
	EdgeBlockLiveTileDataCollection                       *bool                                  `json:"edgeBlockLiveTileDataCollection,omitempty"`
	EdgeBlockPasswordManager                              *bool                                  `json:"edgeBlockPasswordManager,omitempty"`
	EdgeBlockPopups                                       *bool                                  `json:"edgeBlockPopups,omitempty"`
	EdgeBlockPrelaunch                                    *bool                                  `json:"edgeBlockPrelaunch,omitempty"`
	EdgeBlockPrinting                                     *bool                                  `json:"edgeBlockPrinting,omitempty"`
	EdgeBlockSavingHistory                                *bool                                  `json:"edgeBlockSavingHistory,omitempty"`
	EdgeBlockSearchEngineCustomization                    *bool                                  `json:"edgeBlockSearchEngineCustomization,omitempty"`
	EdgeBlockSearchSuggestions                            *bool                                  `json:"edgeBlockSearchSuggestions,omitempty"`
	EdgeBlockSendingDoNotTrackHeader                      *bool                                  `json:"edgeBlockSendingDoNotTrackHeader,omitempty"`
	EdgeBlockSendingIntranetTrafficToInternetExplorer     *bool                                  `json:"edgeBlockSendingIntranetTrafficToInternetExplorer,omitempty"`
	EdgeBlockSideloadingExtensions                        *bool                                  `json:"edgeBlockSideloadingExtensions,omitempty"`
	EdgeBlockTabPreloading                                *bool                                  `json:"edgeBlockTabPreloading,omitempty"`
	EdgeBlockWebContentOnNewTabPage                       *bool                                  `json:"edgeBlockWebContentOnNewTabPage,omitempty"`
	EdgeClearBrowsingDataOnExit                           *bool                                  `json:"edgeClearBrowsingDataOnExit,omitempty"`
	EdgeCookiePolicy                                      *EdgeCookiePolicy                      `json:"edgeCookiePolicy,omitempty"`
	EdgeDisableFirstRunPage                               *bool                                  `json:"edgeDisableFirstRunPage,omitempty"`
	EdgeEnterpriseModeSiteListLocation                    *string                                `json:"edgeEnterpriseModeSiteListLocation,omitempty"`
	EdgeFavoritesBarVisibility                            *VisibilitySetting                     `json:"edgeFavoritesBarVisibility,omitempty"`
	EdgeFavoritesListLocation                             *string                                `json:"edgeFavoritesListLocation,omitempty"`
	EdgeFirstRunUrl                                       *string                                `json:"edgeFirstRunUrl,omitempty"`
	EdgeHomeButtonConfiguration                           *EdgeHomeButtonConfiguration           `json:"edgeHomeButtonConfiguration,omitempty"`
	EdgeHomeButtonConfigurationEnabled                    *bool                                  `json:"edgeHomeButtonConfigurationEnabled,omitempty"`
	EdgeHomepageUrls                                      *[]string                              `json:"edgeHomepageUrls,omitempty"`
	EdgeKioskModeRestriction                              *EdgeKioskModeRestrictionType          `json:"edgeKioskModeRestriction,omitempty"`
	EdgeKioskResetAfterIdleTimeInMinutes                  *int32                                 `json:"edgeKioskResetAfterIdleTimeInMinutes,omitempty"`
	EdgeNewTabPageURL                                     *string                                `json:"edgeNewTabPageURL,omitempty"`
	EdgeOpensWith                                         *EdgeOpenOptions                       `json:"edgeOpensWith,omitempty"`
	EdgePreventCertificateErrorOverride                   *bool                                  `json:"edgePreventCertificateErrorOverride,omitempty"`
	EdgeRequiredExtensionPackageFamilyNames               *[]string                              `json:"edgeRequiredExtensionPackageFamilyNames,omitempty"`
	EdgeRequireSmartScreen                                *bool                                  `json:"edgeRequireSmartScreen,omitempty"`
	EdgeSearchEngine                                      *EdgeSearchEngineBase                  `json:"edgeSearchEngine,omitempty"`
	EdgeSendIntranetTrafficToInternetExplorer             *bool                                  `json:"edgeSendIntranetTrafficToInternetExplorer,omitempty"`
	EdgeShowMessageWhenOpeningInternetExplorerSites       *InternetExplorerMessageSetting        `json:"edgeShowMessageWhenOpeningInternetExplorerSites,omitempty"`
	EdgeSyncFavoritesWithInternetExplorer                 *bool                                  `json:"edgeSyncFavoritesWithInternetExplorer,omitempty"`
	EdgeTelemetryForMicrosoft365Analytics                 *EdgeTelemetryMode                     `json:"edgeTelemetryForMicrosoft365Analytics,omitempty"`
	EnableAutomaticRedeployment                           *bool                                  `json:"enableAutomaticRedeployment,omitempty"`
	EnergySaverOnBatteryThresholdPercentage               *int32                                 `json:"energySaverOnBatteryThresholdPercentage,omitempty"`
	EnergySaverPluggedInThresholdPercentage               *int32                                 `json:"energySaverPluggedInThresholdPercentage,omitempty"`
	EnterpriseCloudPrintDiscoveryEndPoint                 *string                                `json:"enterpriseCloudPrintDiscoveryEndPoint,omitempty"`
	EnterpriseCloudPrintDiscoveryMaxLimit                 *int32                                 `json:"enterpriseCloudPrintDiscoveryMaxLimit,omitempty"`
	EnterpriseCloudPrintMopriaDiscoveryResourceIdentifier *string                                `json:"enterpriseCloudPrintMopriaDiscoveryResourceIdentifier,omitempty"`
	EnterpriseCloudPrintOAuthAuthority                    *string                                `json:"enterpriseCloudPrintOAuthAuthority,omitempty"`
	EnterpriseCloudPrintOAuthClientIdentifier             *string                                `json:"enterpriseCloudPrintOAuthClientIdentifier,omitempty"`
	EnterpriseCloudPrintResourceIdentifier                *string                                `json:"enterpriseCloudPrintResourceIdentifier,omitempty"`
	ExperienceBlockDeviceDiscovery                        *bool                                  `json:"experienceBlockDeviceDiscovery,omitempty"`
	ExperienceBlockErrorDialogWhenNoSIM                   *bool                                  `json:"experienceBlockErrorDialogWhenNoSIM,omitempty"`
	ExperienceBlockTaskSwitcher                           *bool                                  `json:"experienceBlockTaskSwitcher,omitempty"`
	ExperienceDoNotSyncBrowserSettings                    *BrowserSyncSetting                    `json:"experienceDoNotSyncBrowserSettings,omitempty"`
	FindMyFiles                                           *Enablement                            `json:"findMyFiles,omitempty"`
	GameDvrBlocked                                        *bool                                  `json:"gameDvrBlocked,omitempty"`
	InkWorkspaceAccess                                    *InkAccessSetting                      `json:"inkWorkspaceAccess,omitempty"`
	InkWorkspaceAccessState                               *StateManagementSetting                `json:"inkWorkspaceAccessState,omitempty"`
	InkWorkspaceBlockSuggestedApps                        *bool                                  `json:"inkWorkspaceBlockSuggestedApps,omitempty"`
	InternetSharingBlocked                                *bool                                  `json:"internetSharingBlocked,omitempty"`
	LocationServicesBlocked                               *bool                                  `json:"locationServicesBlocked,omitempty"`
	LockScreenActivateAppsWithVoice                       *Enablement                            `json:"lockScreenActivateAppsWithVoice,omitempty"`
	LockScreenAllowTimeoutConfiguration                   *bool                                  `json:"lockScreenAllowTimeoutConfiguration,omitempty"`
	LockScreenBlockActionCenterNotifications              *bool                                  `json:"lockScreenBlockActionCenterNotifications,omitempty"`
	LockScreenBlockCortana                                *bool                                  `json:"lockScreenBlockCortana,omitempty"`
	LockScreenBlockToastNotifications                     *bool                                  `json:"lockScreenBlockToastNotifications,omitempty"`
	LockScreenTimeoutInSeconds                            *int32                                 `json:"lockScreenTimeoutInSeconds,omitempty"`
	LogonBlockFastUserSwitching                           *bool                                  `json:"logonBlockFastUserSwitching,omitempty"`
	MessagingBlockMMS                                     *bool                                  `json:"messagingBlockMMS,omitempty"`
	MessagingBlockRichCommunicationServices               *bool                                  `json:"messagingBlockRichCommunicationServices,omitempty"`
	MessagingBlockSync                                    *bool                                  `json:"messagingBlockSync,omitempty"`
	MicrosoftAccountBlocked                               *bool                                  `json:"microsoftAccountBlocked,omitempty"`
	MicrosoftAccountBlockSettingsSync                     *bool                                  `json:"microsoftAccountBlockSettingsSync,omitempty"`
	MicrosoftAccountSignInAssistantSettings               *SignInAssistantOptions                `json:"microsoftAccountSignInAssistantSettings,omitempty"`
	NetworkProxyApplySettingsDeviceWide                   *bool                                  `json:"networkProxyApplySettingsDeviceWide,omitempty"`
	NetworkProxyAutomaticConfigurationUrl                 *string                                `json:"networkProxyAutomaticConfigurationUrl,omitempty"`
	NetworkProxyDisableAutoDetect                         *bool                                  `json:"networkProxyDisableAutoDetect,omitempty"`
	NetworkProxyServer                                    *Windows10NetworkProxyServer           `json:"networkProxyServer,omitempty"`
	NfcBlocked                                            *bool                                  `json:"nfcBlocked,omitempty"`
	OneDriveDisableFileSync                               *bool                                  `json:"oneDriveDisableFileSync,omitempty"`
	PasswordBlockSimple                                   *bool                                  `json:"passwordBlockSimple,omitempty"`
	PasswordExpirationDays                                *int32                                 `json:"passwordExpirationDays,omitempty"`
	PasswordMinimumAgeInDays                              *int32                                 `json:"passwordMinimumAgeInDays,omitempty"`
	PasswordMinimumCharacterSetCount                      *int32                                 `json:"passwordMinimumCharacterSetCount,omitempty"`
	PasswordMinimumLength                                 *int32                                 `json:"passwordMinimumLength,omitempty"`
	PasswordMinutesOfInactivityBeforeScreenTimeout        *int32                                 `json:"passwordMinutesOfInactivityBeforeScreenTimeout,omitempty"`
	PasswordPreviousPasswordBlockCount                    *int32                                 `json:"passwordPreviousPasswordBlockCount,omitempty"`
	PasswordRequired                                      *bool                                  `json:"passwordRequired,omitempty"`
	PasswordRequiredType                                  *RequiredPasswordType                  `json:"passwordRequiredType,omitempty"`
	PasswordRequireWhenResumeFromIdleState                *bool                                  `json:"passwordRequireWhenResumeFromIdleState,omitempty"`
	PasswordSignInFailureCountBeforeFactoryReset          *int32                                 `json:"passwordSignInFailureCountBeforeFactoryReset,omitempty"`
	PersonalizationDesktopImageUrl                        *string                                `json:"personalizationDesktopImageUrl,omitempty"`
	PersonalizationLockScreenImageUrl                     *string                                `json:"personalizationLockScreenImageUrl,omitempty"`
	PowerButtonActionOnBattery                            *PowerActionType                       `json:"powerButtonActionOnBattery,omitempty"`
	PowerButtonActionPluggedIn                            *PowerActionType                       `json:"powerButtonActionPluggedIn,omitempty"`
	PowerHybridSleepOnBattery                             *Enablement                            `json:"powerHybridSleepOnBattery,omitempty"`
	PowerHybridSleepPluggedIn                             *Enablement                            `json:"powerHybridSleepPluggedIn,omitempty"`
	PowerLidCloseActionOnBattery                          *PowerActionType                       `json:"powerLidCloseActionOnBattery,omitempty"`
	PowerLidCloseActionPluggedIn                          *PowerActionType                       `json:"powerLidCloseActionPluggedIn,omitempty"`
	PowerSleepButtonActionOnBattery                       *PowerActionType                       `json:"powerSleepButtonActionOnBattery,omitempty"`
	PowerSleepButtonActionPluggedIn                       *PowerActionType                       `json:"powerSleepButtonActionPluggedIn,omitempty"`
	PrinterBlockAddition                                  *bool                                  `json:"printerBlockAddition,omitempty"`
	PrinterDefaultName                                    *string                                `json:"printerDefaultName,omitempty"`
	PrinterNames                                          *[]string                              `json:"printerNames,omitempty"`
	PrivacyAdvertisingId                                  *StateManagementSetting                `json:"privacyAdvertisingId,omitempty"`
	PrivacyAutoAcceptPairingAndConsentPrompts             *bool                                  `json:"privacyAutoAcceptPairingAndConsentPrompts,omitempty"`
	PrivacyBlockActivityFeed                              *bool                                  `json:"privacyBlockActivityFeed,omitempty"`
	PrivacyBlockInputPersonalization                      *bool                                  `json:"privacyBlockInputPersonalization,omitempty"`
	PrivacyBlockPublishUserActivities                     *bool                                  `json:"privacyBlockPublishUserActivities,omitempty"`
	PrivacyDisableLaunchExperience                        *bool                                  `json:"privacyDisableLaunchExperience,omitempty"`
	ResetProtectionModeBlocked                            *bool                                  `json:"resetProtectionModeBlocked,omitempty"`
	SafeSearchFilter                                      *SafeSearchFilterType                  `json:"safeSearchFilter,omitempty"`
	ScreenCaptureBlocked                                  *bool                                  `json:"screenCaptureBlocked,omitempty"`
	SearchBlockDiacritics                                 *bool                                  `json:"searchBlockDiacritics,omitempty"`
	SearchBlockWebResults                                 *bool                                  `json:"searchBlockWebResults,omitempty"`
	SearchDisableAutoLanguageDetection                    *bool                                  `json:"searchDisableAutoLanguageDetection,omitempty"`
	SearchDisableIndexerBackoff                           *bool                                  `json:"searchDisableIndexerBackoff,omitempty"`
	SearchDisableIndexingEncryptedItems                   *bool                                  `json:"searchDisableIndexingEncryptedItems,omitempty"`
	SearchDisableIndexingRemovableDrive                   *bool                                  `json:"searchDisableIndexingRemovableDrive,omitempty"`
	SearchDisableLocation                                 *bool                                  `json:"searchDisableLocation,omitempty"`
	SearchDisableUseLocation                              *bool                                  `json:"searchDisableUseLocation,omitempty"`
	SearchEnableAutomaticIndexSizeManangement             *bool                                  `json:"searchEnableAutomaticIndexSizeManangement,omitempty"`
	SearchEnableRemoteQueries                             *bool                                  `json:"searchEnableRemoteQueries,omitempty"`
	SecurityBlockAzureADJoinedDevicesAutoEncryption       *bool                                  `json:"securityBlockAzureADJoinedDevicesAutoEncryption,omitempty"`
	SettingsBlockAccountsPage                             *bool                                  `json:"settingsBlockAccountsPage,omitempty"`
	SettingsBlockAddProvisioningPackage                   *bool                                  `json:"settingsBlockAddProvisioningPackage,omitempty"`
	SettingsBlockAppsPage                                 *bool                                  `json:"settingsBlockAppsPage,omitempty"`
	SettingsBlockChangeLanguage                           *bool                                  `json:"settingsBlockChangeLanguage,omitempty"`
	SettingsBlockChangePowerSleep                         *bool                                  `json:"settingsBlockChangePowerSleep,omitempty"`
	SettingsBlockChangeRegion                             *bool                                  `json:"settingsBlockChangeRegion,omitempty"`
	SettingsBlockChangeSystemTime                         *bool                                  `json:"settingsBlockChangeSystemTime,omitempty"`
	SettingsBlockDevicesPage                              *bool                                  `json:"settingsBlockDevicesPage,omitempty"`
	SettingsBlockEaseOfAccessPage                         *bool                                  `json:"settingsBlockEaseOfAccessPage,omitempty"`
	SettingsBlockEditDeviceName                           *bool                                  `json:"settingsBlockEditDeviceName,omitempty"`
	SettingsBlockGamingPage                               *bool                                  `json:"settingsBlockGamingPage,omitempty"`
	SettingsBlockNetworkInternetPage                      *bool                                  `json:"settingsBlockNetworkInternetPage,omitempty"`
	SettingsBlockPersonalizationPage                      *bool                                  `json:"settingsBlockPersonalizationPage,omitempty"`
	SettingsBlockPrivacyPage                              *bool                                  `json:"settingsBlockPrivacyPage,omitempty"`
	SettingsBlockRemoveProvisioningPackage                *bool                                  `json:"settingsBlockRemoveProvisioningPackage,omitempty"`
	SettingsBlockSettingsApp                              *bool                                  `json:"settingsBlockSettingsApp,omitempty"`
	SettingsBlockSystemPage                               *bool                                  `json:"settingsBlockSystemPage,omitempty"`
	SettingsBlockTimeLanguagePage                         *bool                                  `json:"settingsBlockTimeLanguagePage,omitempty"`
	SettingsBlockUpdateSecurityPage                       *bool                                  `json:"settingsBlockUpdateSecurityPage,omitempty"`
	SharedUserAppDataAllowed                              *bool                                  `json:"sharedUserAppDataAllowed,omitempty"`
	SmartScreenAppInstallControl                          *AppInstallControlType                 `json:"smartScreenAppInstallControl,omitempty"`
	SmartScreenBlockPromptOverride                        *bool                                  `json:"smartScreenBlockPromptOverride,omitempty"`
	SmartScreenBlockPromptOverrideForFiles                *bool                                  `json:"smartScreenBlockPromptOverrideForFiles,omitempty"`
	SmartScreenEnableAppInstallControl                    *bool                                  `json:"smartScreenEnableAppInstallControl,omitempty"`
	StartBlockUnpinningAppsFromTaskbar                    *bool                                  `json:"startBlockUnpinningAppsFromTaskbar,omitempty"`
	StartMenuAppListVisibility                            *WindowsStartMenuAppListVisibilityType `json:"startMenuAppListVisibility,omitempty"`
	StartMenuHideChangeAccountSettings                    *bool                                  `json:"startMenuHideChangeAccountSettings,omitempty"`
	StartMenuHideFrequentlyUsedApps                       *bool                                  `json:"startMenuHideFrequentlyUsedApps,omitempty"`
	StartMenuHideHibernate                                *bool                                  `json:"startMenuHideHibernate,omitempty"`
	StartMenuHideLock                                     *bool                                  `json:"startMenuHideLock,omitempty"`
	StartMenuHidePowerButton                              *bool                                  `json:"startMenuHidePowerButton,omitempty"`
	StartMenuHideRecentJumpLists                          *bool                                  `json:"startMenuHideRecentJumpLists,omitempty"`
	StartMenuHideRecentlyAddedApps                        *bool                                  `json:"startMenuHideRecentlyAddedApps,omitempty"`
	StartMenuHideRestartOptions                           *bool                                  `json:"startMenuHideRestartOptions,omitempty"`
	StartMenuHideShutDown                                 *bool                                  `json:"startMenuHideShutDown,omitempty"`
	StartMenuHideSignOut                                  *bool                                  `json:"startMenuHideSignOut,omitempty"`
	StartMenuHideSleep                                    *bool                                  `json:"startMenuHideSleep,omitempty"`
	StartMenuHideSwitchAccount                            *bool                                  `json:"startMenuHideSwitchAccount,omitempty"`
	StartMenuHideUserTile                                 *bool                                  `json:"startMenuHideUserTile,omitempty"`
	StartMenuLayoutEdgeAssetsXml                          *[]byte                                `json:"startMenuLayoutEdgeAssetsXml,omitempty"`
	StartMenuLayoutXml                                    *[]byte                                `json:"startMenuLayoutXml,omitempty"`
	StartMenuMode                                         *WindowsStartMenuModeType              `json:"startMenuMode,omitempty"`
	StartMenuPinnedFolderDocuments                        *VisibilitySetting                     `json:"startMenuPinnedFolderDocuments,omitempty"`
	StartMenuPinnedFolderDownloads                        *VisibilitySetting                     `json:"startMenuPinnedFolderDownloads,omitempty"`
	StartMenuPinnedFolderFileExplorer                     *VisibilitySetting                     `json:"startMenuPinnedFolderFileExplorer,omitempty"`
	StartMenuPinnedFolderHomeGroup                        *VisibilitySetting                     `json:"startMenuPinnedFolderHomeGroup,omitempty"`
	StartMenuPinnedFolderMusic                            *VisibilitySetting                     `json:"startMenuPinnedFolderMusic,omitempty"`
	StartMenuPinnedFolderNetwork                          *VisibilitySetting                     `json:"startMenuPinnedFolderNetwork,omitempty"`
	StartMenuPinnedFolderPersonalFolder                   *VisibilitySetting                     `json:"startMenuPinnedFolderPersonalFolder,omitempty"`
	StartMenuPinnedFolderPictures                         *VisibilitySetting                     `json:"startMenuPinnedFolderPictures,omitempty"`
	StartMenuPinnedFolderSettings                         *VisibilitySetting                     `json:"startMenuPinnedFolderSettings,omitempty"`
	StartMenuPinnedFolderVideos                           *VisibilitySetting                     `json:"startMenuPinnedFolderVideos,omitempty"`
	StorageBlockRemovableStorage                          *bool                                  `json:"storageBlockRemovableStorage,omitempty"`
	StorageRequireMobileDeviceEncryption                  *bool                                  `json:"storageRequireMobileDeviceEncryption,omitempty"`
	StorageRestrictAppDataToSystemVolume                  *bool                                  `json:"storageRestrictAppDataToSystemVolume,omitempty"`
	StorageRestrictAppInstallToSystemVolume               *bool                                  `json:"storageRestrictAppInstallToSystemVolume,omitempty"`
	SystemTelemetryProxyServer                            *string                                `json:"systemTelemetryProxyServer,omitempty"`
	TaskManagerBlockEndTask                               *bool                                  `json:"taskManagerBlockEndTask,omitempty"`
	TenantLockdownRequireNetworkDuringOutOfBoxExperience  *bool                                  `json:"tenantLockdownRequireNetworkDuringOutOfBoxExperience,omitempty"`
	UninstallBuiltInApps                                  *bool                                  `json:"uninstallBuiltInApps,omitempty"`
	UsbBlocked                                            *bool                                  `json:"usbBlocked,omitempty"`
	VoiceRecordingBlocked                                 *bool                                  `json:"voiceRecordingBlocked,omitempty"`
	WebRtcBlockLocalhostIpAddress                         *bool                                  `json:"webRtcBlockLocalhostIpAddress,omitempty"`
	WiFiBlockAutomaticConnectHotspots                     *bool                                  `json:"wiFiBlockAutomaticConnectHotspots,omitempty"`
	WiFiBlocked                                           *bool                                  `json:"wiFiBlocked,omitempty"`
	WiFiBlockManualConfiguration                          *bool                                  `json:"wiFiBlockManualConfiguration,omitempty"`
	WiFiScanInterval                                      *int32                                 `json:"wiFiScanInterval,omitempty"`
	Windows10AppsForceUpdateSchedule                      *Windows10AppsForceUpdateSchedule      `json:"windows10AppsForceUpdateSchedule,omitempty"`
	WindowsSpotlightBlockConsumerSpecificFeatures         *bool                                  `json:"windowsSpotlightBlockConsumerSpecificFeatures,omitempty"`
	WindowsSpotlightBlocked                               *bool                                  `json:"windowsSpotlightBlocked,omitempty"`
	WindowsSpotlightBlockOnActionCenter                   *bool                                  `json:"windowsSpotlightBlockOnActionCenter,omitempty"`
	WindowsSpotlightBlockTailoredExperiences              *bool                                  `json:"windowsSpotlightBlockTailoredExperiences,omitempty"`
	WindowsSpotlightBlockThirdPartyNotifications          *bool                                  `json:"windowsSpotlightBlockThirdPartyNotifications,omitempty"`
	WindowsSpotlightBlockWelcomeExperience                *bool                                  `json:"windowsSpotlightBlockWelcomeExperience,omitempty"`
	WindowsSpotlightBlockWindowsTips                      *bool                                  `json:"windowsSpotlightBlockWindowsTips,omitempty"`
	WindowsSpotlightConfigureOnLockScreen                 *WindowsSpotlightEnablementSettings    `json:"windowsSpotlightConfigureOnLockScreen,omitempty"`
	WindowsStoreBlockAutoUpdate                           *bool                                  `json:"windowsStoreBlockAutoUpdate,omitempty"`
	WindowsStoreBlocked                                   *bool                                  `json:"windowsStoreBlocked,omitempty"`
	WindowsStoreEnablePrivateStoreOnly                    *bool                                  `json:"windowsStoreEnablePrivateStoreOnly,omitempty"`
	WirelessDisplayBlockProjectionToThisDevice            *bool                                  `json:"wirelessDisplayBlockProjectionToThisDevice,omitempty"`
	WirelessDisplayBlockUserInputFromReceiver             *bool                                  `json:"wirelessDisplayBlockUserInputFromReceiver,omitempty"`
	WirelessDisplayRequirePinForPairing                   *bool                                  `json:"wirelessDisplayRequirePinForPairing,omitempty"`
}

func (a Windows10GeneralConfiguration) GetConfigurationBase() *DeviceConfigurationBase {
	return &a.DeviceConfigurationBase
}

type EdgeSearchEngineBase struct {
}

type Windows10NetworkProxyServer struct {
	Address              *string   `json:"address,omitempty"`
	Exceptions           *[]string `json:"exceptions,omitempty"`
	UseForLocalAddresses *bool     `json:"useForLocalAddresses,omitempty"`
}

type Windows10AppsForceUpdateSchedule struct {
	Recurrence                         *Windows10AppsUpdateRecurrence `json:"recurrence,omitempty"`
	RunImmediatelyIfAfterStartDateTime *bool                          `json:"runImmediatelyIfAfterStartDateTime,omitempty"`
	StartDateTime                      *time.Time                     `json:"startDateTime,omitempty"`
}

type DeviceManagementApplicabilityRuleDeviceMode struct {
	DeviceMode *Windows10DeviceModeType               `json:"deviceMode,omitempty"`
	Name       *string                                `json:"name,omitempty"`
	RuleType   *DeviceManagementApplicabilityRuleType `json:"ruleType,omitempty"`
}

type DeviceManagementApplicabilityRuleOsVersion struct {
	MaxOSVersion *string                                `json:"maxOSVersion,omitempty"`
	MinOSVersion *string                                `json:"minOSVersion,omitempty"`
	Name         *string                                `json:"name,omitempty"`
	RuleType     *DeviceManagementApplicabilityRuleType `json:"ruleType,omitempty"`
}

type DefenderDetectedMalwareActions struct {
	HighSeverity     *DefenderThreatAction `json:"highSeverity,omitempty"`
	LowSeverity      *DefenderThreatAction `json:"lowSeverity,omitempty"`
	ModerateSeverity *DefenderThreatAction `json:"moderateSeverity,omitempty"`
	SevereSeverity   *DefenderThreatAction `json:"severeSeverity,omitempty"`
}

type AospDeviceOwnerDeviceConfiguration struct {
	DeviceConfigurationBase

	AppsBlockInstallFromUnknownSources             *bool                                   `json:"appsBlockInstallFromUnknownSources,omitempty"`
	BluetoothBlockConfiguration                    *bool                                   `json:"bluetoothBlockConfiguration,omitempty"`
	BluetoothBlocked                               *bool                                   `json:"bluetoothBlocked,omitempty"`
	CameraBlocked                                  *bool                                   `json:"cameraBlocked,omitempty"`
	FactoryResetBlocked                            *bool                                   `json:"factoryResetBlocked,omitempty"`
	PasswordMinimumLength                          *int32                                  `json:"passwordMinimumLength,omitempty"`
	PasswordMinutesOfInactivityBeforeScreenTimeout *int32                                  `json:"passwordMinutesOfInactivityBeforeScreenTimeout,omitempty"`
	PasswordRequiredType                           *AndroidDeviceOwnerRequiredPasswordType `json:"passwordRequiredType,omitempty"`
	PasswordSignInFailureCountBeforeFactoryReset   *int32                                  `json:"passwordSignInFailureCountBeforeFactoryReset,omitempty"`
	ScreenCaptureBlocked                           *bool                                   `json:"screenCaptureBlocked,omitempty"`
	SecurityAllowDebuggingFeatures                 *bool                                   `json:"securityAllowDebuggingFeatures,omitempty"`
	StorageBlockExternalMedia                      *bool                                   `json:"storageBlockExternalMedia,omitempty"`
	StorageBlockUsbFileTransfer                    *bool                                   `json:"storageBlockUsbFileTransfer,omitempty"`
	WifiBlockEditConfigurations                    *bool                                   `json:"wifiBlockEditConfigurations,omitempty"`
}

func (a AospDeviceOwnerDeviceConfiguration) GetConfigurationBase() *DeviceConfigurationBase {
	return &a.DeviceConfigurationBase
}

type OmaSetting struct {
	Description            *string `json:"description,omitempty"`
	DisplayName            *string `json:"displayName,omitempty"`
	IsEncrypted            *bool   `json:"isEncrypted,omitempty"`
	OmaUri                 *string `json:"omaUri,omitempty"`
	SecretReferenceValueId *string `json:"secretReferenceValueId,omitempty"`
}

type Windows10CustomConfiguration struct {
	DeviceConfigurationBase

	OmaSettings *[]OmaSetting `json:"omaSettings,omitempty"`
}

func (a Windows10CustomConfiguration) GetConfigurationBase() *DeviceConfigurationBase {
	return &a.DeviceConfigurationBase
}

type DeviceManagementConfigurationChoiceSettingValue struct {
	DeviceManagementConfigurationSettingValue
	Children *[]DeviceManagementConfigurationSettingInstance `json:"children,omitempty"`
	Value    *string                                         `json:"value,omitempty"`
}

type DeviceManagementConfigurationSettingValue struct {
	SettingValueTemplateReference *DeviceManagementConfigurationSettingValueTemplateReference `json:"settingValueTemplateReference,omitempty"`
}

type DeviceManagementConfigurationSettingValueTemplateReference struct {
	SettingValueTemplateId *string `json:"settingValueTemplateId,omitempty"`
	UseTemplateDefault     *bool   `json:"useTemplateDefault,omitempty"`
}

type DeviceManagementConfigurationChoiceSettingInstance struct {
	DeviceManagementConfigurationSettingInstance
	ChoiceSettingValue *DeviceManagementConfigurationChoiceSettingValue `json:"choiceSettingValue,omitempty"`
}

type DeviceManagementConfigurationSettingInstance struct {
	SettingDefinitionId              *string                                                        `json:"settingDefinitionId,omitempty"`
	SettingInstanceTemplateReference *DeviceManagementConfigurationSettingInstanceTemplateReference `json:"settingInstanceTemplateReference,omitempty"`
}

type DeviceManagementConfigurationSettingInstanceTemplateReference struct {
	SettingInstanceTemplateId *string `json:"settingInstanceTemplateId,omitempty"`
}

type DeviceManagementConfigurationSetting struct {
	Entity

	SettingInstance *DeviceManagementConfigurationSettingInstance `json:"settingInstance,omitempty"`
}
