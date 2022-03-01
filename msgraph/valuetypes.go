package msgraph

import (
	"encoding/json"
	goerrors "errors"

	"github.com/manicminer/hamilton/odata"
)

// NullableString returns a pointer to a StringNullWhenEmpty for use in model structs
func NullableString(s StringNullWhenEmpty) *StringNullWhenEmpty { return &s }

// StringNullWhenEmpty is a string type that marshals its JSON representation as null when set to its zero value.
// Can be used with a pointer reference with the `omitempty` tag to omit a field when the pointer is nil, but send a
// JSON null value when the string is empty.
type StringNullWhenEmpty string

func (s StringNullWhenEmpty) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(s))
}

type AccessPackageCatalogState = string

const (
	AccessPackageCatalogStatePublished   AccessPackageCatalogState = "published"
	AccessPackageCatalogStateUnpublished AccessPackageCatalogState = "unpublished"
)

type AccessPackageCatalogStatus = string

const (
	AccessPackageCatalogStatusPublished   AccessPackageCatalogStatus = "Published"
	AccessPackageCatalogStatusUnpublished AccessPackageCatalogState  = "Unpublished"
)

type AccessPackageCatalogType = string

const (
	AccessPackageCatalogTypeServiceDefault AccessPackageCatalogType = "ServiceDefault"
	AccessPackageCatalogTypeUserManaged    AccessPackageCatalogType = "UserManaged"
)

type AccessPackageResourceOriginSystem = string

const (
	AccessPackageResourceOriginSystemAadApplication   AccessPackageResourceOriginSystem = "AadApplication"
	AccessPackageResourceOriginSystemAadGroup         AccessPackageResourceOriginSystem = "AadGroup"
	AccessPackageResourceOriginSystemSharePointOnline AccessPackageResourceOriginSystem = "SharePointOnline"
)

type AccessPackageResourceRequestState = string

const (
	AccessPackageResourceRequestStateDelivered AccessPackageResourceRequestState = "Delivered"
)

type AccessPackageResourceRequestType = string

const (
	AccessPackageResourceRequestTypeAdminAdd    AccessPackageResourceRequestType = "AdminAdd"
	AccessPackageResourceRequestTypeAdminRemove AccessPackageResourceRequestType = "AdminRemove"
)

type AccessPackageResourceType = string

const (
	AccessPackageResourceTypeApplication          AccessPackageResourceType = "Application"
	AccessPackageResourceTypeSharePointOnlineSite AccessPackageResourceType = "SharePoint Online Site"
)

type AccessReviewTimeoutBehaviorType = string

const (
	AccessReviewTimeoutBehaviorTypeAcceptAccessRecommendation AccessReviewTimeoutBehaviorType = "acceptAccessRecommendation"
	AccessReviewTimeoutBehaviorTypeKeepAccess                 AccessReviewTimeoutBehaviorType = "keepAccess"
	AccessReviewTimeoutBehaviorTypeRemoveAccess               AccessReviewTimeoutBehaviorType = "removeAccess"
)

type AccessReviewReviewerType = string

const (
	AccessReviewReviewerTypeSelf      AccessReviewReviewerType = "Self"
	AccessReviewReviewerTypeReviewers AccessReviewReviewerType = "Reviewers"
)

type AccessReviewRecurranceType = string

const (
	AccessReviewRecurranceTypeWeekly     AccessReviewRecurranceType = "weekly"
	AccessReviewRecurranceTypeMonthly    AccessReviewRecurranceType = "monthly"
	AccessReviewRecurranceTypeQuarterly  AccessReviewRecurranceType = "quarterly"
	AccessReviewRecurranceTypeHalfYearly AccessReviewRecurranceType = "halfyearly"
	AccessReviewRecurranceTypeAnnual     AccessReviewRecurranceType = "annual"
)

type AdministrativeUnitVisibility = string

const (
	AdministrativeUnitVisibilityHiddenMembership AdministrativeUnitVisibility = "HiddenMembership"
	AdministrativeUnitVisibilityPublic           AdministrativeUnitVisibility = "Public"
)

type AgeGroup = StringNullWhenEmpty

const (
	AgeGroupNone     AgeGroup = ""
	AgeGroupAdult    AgeGroup = "Adult"
	AgeGroupMinor    AgeGroup = "Minor"
	AgeGroupNotAdult AgeGroup = "NotAdult"
)

type ApplicationExtensionDataType = string

const (
	ApplicationExtensionDataTypeBinary       ApplicationExtensionDataType = "Binary"
	ApplicationExtensionDataTypeBoolean      ApplicationExtensionDataType = "Boolean"
	ApplicationExtensionDataTypeDateTime     ApplicationExtensionDataType = "DateTime"
	ApplicationExtensionDataTypeInteger      ApplicationExtensionDataType = "Integer"
	ApplicationExtensionDataTypeLargeInteger ApplicationExtensionDataType = "LargeInteger"
	ApplicationExtensionDataTypeString       ApplicationExtensionDataType = "String"
)

type ApplicationExtensionTargetObject = string

const (
	ApplicationExtensionTargetObjectApplication  ApplicationExtensionTargetObject = "Application"
	ApplicationExtensionTargetObjectDevice       ApplicationExtensionTargetObject = "Device"
	ApplicationExtensionTargetObjectGroup        ApplicationExtensionTargetObject = "Group"
	ApplicationExtensionTargetObjectOrganization ApplicationExtensionTargetObject = "Organization"
	ApplicationExtensionTargetObjectUser         ApplicationExtensionTargetObject = "User"
)

type ApplicationTemplateCategory = string

const (
	ApplicationTemplateCategoryCollaboration      ApplicationTemplateCategory = "Collaboration"
	ApplicationTemplateCategoryBusinessManagement ApplicationTemplateCategory = "Business Management"
	ApplicationTemplateCategoryConsumer           ApplicationTemplateCategory = "Consumer"
	ApplicationTemplateCategoryContentManagement  ApplicationTemplateCategory = "Content management"
	ApplicationTemplateCategoryCRM                ApplicationTemplateCategory = "CRM"
	ApplicationTemplateCategoryDataServices       ApplicationTemplateCategory = "Data services"
	ApplicationTemplateCategoryDeveloperServices  ApplicationTemplateCategory = "Developer services"
	ApplicationTemplateCategoryECommerce          ApplicationTemplateCategory = "E-commerce"
	ApplicationTemplateCategoryEducation          ApplicationTemplateCategory = "Education"
	ApplicationTemplateCategoryERP                ApplicationTemplateCategory = "ERP"
	ApplicationTemplateCategoryFinance            ApplicationTemplateCategory = "Finance"
	ApplicationTemplateCategoryHealth             ApplicationTemplateCategory = "Health"
	ApplicationTemplateCategoryHumanResources     ApplicationTemplateCategory = "Human resources"
	ApplicationTemplateCategoryITInfrastructure   ApplicationTemplateCategory = "IT infrastructure"
	ApplicationTemplateCategoryMail               ApplicationTemplateCategory = "Mail"
	ApplicationTemplateCategoryManagement         ApplicationTemplateCategory = "Management"
	ApplicationTemplateCategoryMarketing          ApplicationTemplateCategory = "Marketing"
	ApplicationTemplateCategoryMedia              ApplicationTemplateCategory = "Media"
	ApplicationTemplateCategoryProductivity       ApplicationTemplateCategory = "Productivity"
	ApplicationTemplateCategoryProjectManagement  ApplicationTemplateCategory = "Project management"
	ApplicationTemplateCategoryTelecommunications ApplicationTemplateCategory = "Telecommunications"
	ApplicationTemplateCategoryTools              ApplicationTemplateCategory = "Tools"
	ApplicationTemplateCategoryTravel             ApplicationTemplateCategory = "Travel"
	ApplicationTemplateCategoryWebDesignHosting   ApplicationTemplateCategory = "Web design & hosting"
)

type AppRoleAllowedMemberType = string

const (
	AppRoleAllowedMemberTypeApplication AppRoleAllowedMemberType = "Application"
	AppRoleAllowedMemberTypeUser        AppRoleAllowedMemberType = "User"
)

type ApprovalMode = string

const (
	ApprovalModeNoApproval  ApprovalMode = "NoApproval"
	ApprovalModeSerial      ApprovalMode = "Serial"
	ApprovalModeSingleStage ApprovalMode = "SingleStage"
)

type AttestationLevel = string

const (
	AttestationLevelAttested    AttestationLevel = "attested"
	AttestationLevelNotAttested AttestationLevel = "notAttested"
)

type AuthenticationMethodFeature = string

const (
	AuthenticationMethodFeatureSsprRegistered      AuthenticationMethodFeature = "ssprRegistered"
	AuthenticationMethodFeatureSsprEnabled         AuthenticationMethodFeature = "ssprEnabled"
	AuthenticationMethodFeatureSsprCapable         AuthenticationMethodFeature = "ssprCapable"
	AuthenticationMethodFeaturePasswordlessCapable AuthenticationMethodFeature = "passwordlessCapable"
	AuthenticationMethodFeatureMfaCapable          AuthenticationMethodFeature = "mfaCapable"
)

type AuthenticationMethodKeyStrength = string

const (
	AuthenticationMethodKeyStrengthNormal  AuthenticationMethodKeyStrength = "normal"
	AuthenticationMethodKeyStrengthWeak    AuthenticationMethodKeyStrength = "weak"
	AuthenticationMethodKeyStrengthUnknown AuthenticationMethodKeyStrength = "unknown"
)

type AuthenticationPhoneType = string

const (
	AuthenticationPhoneTypeMobile          AuthenticationPhoneType = "mobile"
	AuthenticationPhoneTypeAlternateMobile AuthenticationPhoneType = "alternateMobile"
	AuthenticationPhoneTypeOffice          AuthenticationPhoneType = "office"
)

type BodyType = string

const (
	BodyTypeText BodyType = "text"
	BodyTypeHtml BodyType = "html"
)

type ConsentProvidedForMinor = StringNullWhenEmpty

const (
	ConsentProvidedForMinorNone        ConsentProvidedForMinor = ""
	ConsentProvidedForMinorDenied      ConsentProvidedForMinor = "Denied"
	ConsentProvidedForMinorGranted     ConsentProvidedForMinor = "Granted"
	ConsentProvidedForMinorNotRequired ConsentProvidedForMinor = "NotRequired"
)

type CredentialUsageSummaryPeriod = string

const (
	CredentialUsageSummaryPeriod30 CredentialUsageSummaryPeriod = "D30"
	CredentialUsageSummaryPeriod7  CredentialUsageSummaryPeriod = "D7"
	CredentialUsageSummaryPeriod1  CredentialUsageSummaryPeriod = "D1"
)

type ConditionalAccessClientAppType = string

const (
	ConditionalAccessClientAppTypeAll                         ConditionalAccessClientAppType = "all"
	ConditionalAccessClientAppTypeBrowser                     ConditionalAccessClientAppType = "browser"
	ConditionalAccessClientAppTypeEasSupported                ConditionalAccessClientAppType = "easSupported"
	ConditionalAccessClientAppTypeExchangeActiveSync          ConditionalAccessClientAppType = "exchangeActiveSync"
	ConditionalAccessClientAppTypeMobileAppsAndDesktopClients ConditionalAccessClientAppType = "mobileAppsAndDesktopClients"
	ConditionalAccessClientAppTypeOther                       ConditionalAccessClientAppType = "other"
)

type ConditionalAccessCloudAppSecuritySessionControlType = string

const (
	ConditionalAccessCloudAppSecuritySessionControlTypeBlockDownloads     ConditionalAccessCloudAppSecuritySessionControlType = "blockDownloads"
	ConditionalAccessCloudAppSecuritySessionControlTypeMcasConfigured     ConditionalAccessCloudAppSecuritySessionControlType = "mcasConfigured"
	ConditionalAccessCloudAppSecuritySessionControlTypeMonitorOnly        ConditionalAccessCloudAppSecuritySessionControlType = "monitorOnly"
	ConditionalAccessCloudAppSecuritySessionControlTypeUnknownFutureValue ConditionalAccessCloudAppSecuritySessionControlType = "unknownFutureValue"
)

type ConditionalAccessDevicePlatform = string

const (
	ConditionalAccessDevicePlatformAll                ConditionalAccessDevicePlatform = "all"
	ConditionalAccessDevicePlatformAndroid            ConditionalAccessDevicePlatform = "android"
	ConditionalAccessDevicePlatformIos                ConditionalAccessDevicePlatform = "iOS"
	ConditionalAccessDevicePlatformMacOs              ConditionalAccessDevicePlatform = "macOS"
	ConditionalAccessDevicePlatformUnknownFutureValue ConditionalAccessDevicePlatform = "unknownFutureValue"
	ConditionalAccessDevicePlatformWindows            ConditionalAccessDevicePlatform = "windows"
	ConditionalAccessDevicePlatformWindowsPhone       ConditionalAccessDevicePlatform = "windowsPhone"
)

type ConditionalAccessDeviceStatesInclude = string

const (
	ConditionalAccessDeviceStatesIncludeAll ConditionalAccessDeviceStatesInclude = "All"
)

type ConditionalAccessDeviceStatesExclude = string

const (
	ConditionalAccessDeviceStatesExcludeCompliant    ConditionalAccessDeviceStatesExclude = "Compliant"
	ConditionalAccessDeviceStatesExcludeDomainJoined ConditionalAccessDeviceStatesExclude = "DomainJoined"
)

type ConditionalAccessFilterMode = string

const (
	ConditionalAccessFilterModeExclude ConditionalAccessFilterMode = "exclude"
	ConditionalAccessFilterModeInclude ConditionalAccessFilterMode = "include"
)

type ConditionalAccessGrantControl = string

const (
	ConditionalAccessGrantControlApprovedApplication  ConditionalAccessGrantControl = "approvedApplication"
	ConditionalAccessGrantControlBlock                ConditionalAccessGrantControl = "block"
	ConditionalAccessGrantControlCompliantApplication ConditionalAccessGrantControl = "compliantApplication"
	ConditionalAccessGrantControlCompliantDevice      ConditionalAccessGrantControl = "compliantDevice"
	ConditionalAccessGrantControlDomainJoinedDevice   ConditionalAccessGrantControl = "domainJoinedDevice"
	ConditionalAccessGrantControlMfa                  ConditionalAccessGrantControl = "mfa"
	ConditionalAccessGrantControlPasswordChange       ConditionalAccessGrantControl = "passwordChange"
	ConditionalAccessGrantControlUnknownFutureValue   ConditionalAccessGrantControl = "unknownFutureValue"
)

type ConditionalAccessPolicyState = string

const (
	ConditionalAccessPolicyStateEnabled                           ConditionalAccessPolicyState = "enabled"
	ConditionalAccessPolicyStateDisabled                          ConditionalAccessPolicyState = "disabled"
	ConditionalAccessPolicyStateEnabledForReportingButNotEnforced ConditionalAccessPolicyState = "enabledForReportingButNotEnforced"
)

type ConditionalAccessRiskLevel = string

const (
	ConditionalAccessRiskLevelHidden             ConditionalAccessRiskLevel = "hidden"
	ConditionalAccessRiskLevelHigh               ConditionalAccessRiskLevel = "high"
	ConditionalAccessRiskLevelLow                ConditionalAccessRiskLevel = "low"
	ConditionalAccessRiskLevelMedium             ConditionalAccessRiskLevel = "medium"
	ConditionalAccessRiskLevelNone               ConditionalAccessRiskLevel = "none"
	ConditionalAccessRiskLevelUnknownFutureValue ConditionalAccessRiskLevel = "unknownFutureValue"
)

type DelegatedPermissionGrantConsentType = string

const (
	DelegatedPermissionGrantConsentTypeAllPrincipals DelegatedPermissionGrantConsentType = "AllPrincipals"
	DelegatedPermissionGrantConsentTypePrincipal     DelegatedPermissionGrantConsentType = "Principal"
)

type ExtensionSchemaTargetType = string

const (
	ExtensionSchemaTargetTypeAdministrativeUnit ExtensionSchemaTargetType = "AdministrativeUnit"
	ExtensionSchemaTargetTypeContact            ExtensionSchemaTargetType = "Contact"
	ExtensionSchemaTargetTypeDevice             ExtensionSchemaTargetType = "Device"
	ExtensionSchemaTargetTypeEvent              ExtensionSchemaTargetType = "Event"
	ExtensionSchemaTargetTypePost               ExtensionSchemaTargetType = "Post"
	ExtensionSchemaTargetTypeGroup              ExtensionSchemaTargetType = "Group"
	ExtensionSchemaTargetTypeMessage            ExtensionSchemaTargetType = "Message"
	ExtensionSchemaTargetTypeOrganization       ExtensionSchemaTargetType = "Organization"
	ExtensionSchemaTargetTypeUser               ExtensionSchemaTargetType = "User"
)

type ExtensionSchemaPropertyDataType = string

const (
	ExtensionSchemaPropertyDataBinary   ExtensionSchemaPropertyDataType = "Binary"
	ExtensionSchemaPropertyDataBoolean  ExtensionSchemaPropertyDataType = "Boolean"
	ExtensionSchemaPropertyDataDateTime ExtensionSchemaPropertyDataType = "DateTime"
	ExtensionSchemaPropertyDataInteger  ExtensionSchemaPropertyDataType = "Integer"
	ExtensionSchemaPropertyDataString   ExtensionSchemaPropertyDataType = "String"
)

type FeatureType = string

const (
	FeatureTypeRegistration       FeatureType = "registration"
	FeatureTypeReset              FeatureType = "reset"
	FeatureTypeUnknownFutureValue FeatureType = "unknownFutureValue"
)

type GroupMembershipRuleProcessingState = string

const (
	GroupMembershipRuleProcessingStateOn     GroupMembershipRuleProcessingState = "On"
	GroupMembershipRuleProcessingStatePaused GroupMembershipRuleProcessingState = "Paused"
)

type GroupType = string

const (
	GroupTypeDynamicMembership GroupType = "DynamicMembership"
	GroupTypeUnified           GroupType = "Unified"
)

type GroupMembershipClaim = string

const (
	GroupMembershipClaimAll              GroupMembershipClaim = "All"
	GroupMembershipClaimNone             GroupMembershipClaim = "None"
	GroupMembershipClaimApplicationGroup GroupMembershipClaim = "ApplicationGroup"
	GroupMembershipClaimDirectoryRole    GroupMembershipClaim = "DirectoryRole"
	GroupMembershipClaimSecurityGroup    GroupMembershipClaim = "SecurityGroup"
)

type GroupResourceBehaviorOption = string

const (
	GroupResourceBehaviorOptionAllowOnlyMembersToPost   GroupResourceBehaviorOption = "AllowOnlyMembersToPost"
	GroupResourceBehaviorOptionHideGroupInOutlook       GroupResourceBehaviorOption = "HideGroupInOutlook"
	GroupResourceBehaviorOptionSubscribeNewGroupMembers GroupResourceBehaviorOption = "SubscribeNewGroupMembers"
	GroupResourceBehaviorOptionWelcomeEmailDisabled     GroupResourceBehaviorOption = "WelcomeEmailDisabled"
)

type GroupResourceProvisioningOption = string

const (
	GroupResourceProvisioningOptionTeam GroupResourceProvisioningOption = "Team"
)

type GroupTheme = StringNullWhenEmpty

const (
	GroupThemeNone   GroupTheme = ""
	GroupThemeBlue   GroupTheme = "Blue"
	GroupThemeGreen  GroupTheme = "Green"
	GroupThemeOrange GroupTheme = "Orange"
	GroupThemePink   GroupTheme = "Pink"
	GroupThemePurple GroupTheme = "Purple"
	GroupThemeRed    GroupTheme = "Red"
	GroupThemeTeal   GroupTheme = "Teal"
)

type GroupVisibility = string

const (
	GroupVisibilityHiddenMembership GroupVisibility = "Hiddenmembership"
	GroupVisibilityPrivate          GroupVisibility = "Private"
	GroupVisibilityPublic           GroupVisibility = "Public"
)

type InvitedUserType = string

const (
	InvitedUserTypeGuest  InvitedUserType = "Guest"
	InvitedUserTypeMember InvitedUserType = "Member"
)

type KeyCredentialType = string

const (
	KeyCredentialTypeAsymmetricX509Cert  KeyCredentialType = "AsymmetricX509Cert"
	KeyCredentialTypeX509CertAndPassword KeyCredentialType = "X509CertAndPassword"
)

type KeyCredentialUsage = string

const (
	KeyCredentialUsageSign   KeyCredentialUsage = "Sign"
	KeyCredentialUsageVerify KeyCredentialUsage = "Verify"
)

type Members []DirectoryObject

func (o Members) MarshalJSON() ([]byte, error) {
	members := make([]odata.Id, len(o))
	for i, v := range o {
		if v.ODataId == nil {
			return nil, goerrors.New("marshaling Members: encountered DirectoryObject with nil ODataId")
		}
		members[i] = *v.ODataId
	}
	return json.Marshal(members)
}

func (o *Members) UnmarshalJSON(data []byte) error {
	var members []odata.Id
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	for _, v := range members {
		*o = append(*o, DirectoryObject{ODataId: &v})
	}
	return nil
}

type MethodUsabilityReason string

const (
	MethodUsabilityReasonEnabledByPolicy  MethodUsabilityReason = "enabledByPolicy"
	MethodUsabilityReasonDisabledByPolicy MethodUsabilityReason = "disabledByPolicy"
	MethodUsabilityReasonExpired          MethodUsabilityReason = "expired"
	MethodUsabilityReasonNotYetValid      MethodUsabilityReason = "notYetValid"
	MethodUsabilityReasonOneTimeUsed      MethodUsabilityReason = "oneTimeUsed"
)

type Owners []DirectoryObject

func (o Owners) MarshalJSON() ([]byte, error) {
	owners := make([]odata.Id, len(o))
	for i, v := range o {
		if v.ODataId == nil {
			return nil, goerrors.New("marshaling Owners: encountered DirectoryObject with nil ODataId")
		}
		owners[i] = *v.ODataId
	}
	return json.Marshal(owners)
}

func (o *Owners) UnmarshalJSON(data []byte) error {
	var owners []odata.Id
	if err := json.Unmarshal(data, &owners); err != nil {
		return err
	}
	for _, v := range owners {
		*o = append(*o, DirectoryObject{ODataId: &v})
	}
	return nil
}

type PermissionScopeType = string

const (
	PermissionScopeTypeAdmin PermissionScopeType = "Admin"
	PermissionScopeTypeUser  PermissionScopeType = "User"
)

type PersistentBrowserSessionMode = string

const (
	PersistentBrowserSessionModeAlways PersistentBrowserSessionMode = "always"
	PersistentBrowserSessionModeNever  PersistentBrowserSessionMode = "never"
)

type PreferredSingleSignOnMode = StringNullWhenEmpty

const (
	PreferredSingleSignOnModeNone         PreferredSingleSignOnMode = ""
	PreferredSingleSignOnModeNotSupported PreferredSingleSignOnMode = "notSupported"
	PreferredSingleSignOnModeOidc         PreferredSingleSignOnMode = "oidc"
	PreferredSingleSignOnModePassword     PreferredSingleSignOnMode = "password"
	PreferredSingleSignOnModeSaml         PreferredSingleSignOnMode = "saml"
)

type RegistrationAuthMethod = string

const (
	RegistrationAuthMethodEmail                RegistrationAuthMethod = "email"
	RegistrationAuthMethodMobilePhone          RegistrationAuthMethod = "mobilePhone"
	RegistrationAuthMethodOfficePhone          RegistrationAuthMethod = "officePhone"
	RegistrationAuthMethodSecurityQuestion     RegistrationAuthMethod = "securityQuestion"
	RegistrationAuthMethodAppNotification      RegistrationAuthMethod = "appNotification"
	RegistrationAuthMethodAppCode              RegistrationAuthMethod = "appCode"
	RegistrationAuthMethodAlternateMobilePhone RegistrationAuthMethod = "alternateMobilePhone"
	RegistrationAuthMethodFido                 RegistrationAuthMethod = "fido"
	RegistrationAuthMethodAppPassword          RegistrationAuthMethod = "appPassword"
	RegistrationAuthMethodUnknownFutureValue   RegistrationAuthMethod = "unknownFutureValue"
)

type RegistrationStatus = string

const (
	RegistrationStatusRegistered    RegistrationStatus = "registered"
	RegistrationStatusEnabled       RegistrationStatus = "enabled"
	RegistrationStatusCapable       RegistrationStatus = "capable"
	RegistrationStatusMfaRegistered RegistrationStatus = "mfaRegistered"
)

type RequestorSettingsScopeType = string

const (
	RequestorSettingsScopeTypeAllConfiguredConnectedOrganizationSubjects RequestorSettingsScopeType = "AllConfiguredConnectedOrganizationSubjects"
	RequestorSettingsScopeTypeAllExistingConnectedOrganizationSubjects   RequestorSettingsScopeType = "AllExistingConnectedOrganizationSubjects"
	RequestorSettingsScopeTypeAllExistingDirectoryMemberUsers            RequestorSettingsScopeType = "AllExistingDirectoryMemberUsers"
	RequestorSettingsScopeTypeAllExistingDirectorySubjects               RequestorSettingsScopeType = "AllExistingDirectorySubjects"
	RequestorSettingsScopeTypeAllExternalSubjects                        RequestorSettingsScopeType = "AllExternalSubjects"
	RequestorSettingsScopeTypeNoSubjects                                 RequestorSettingsScopeType = "NoSubjects"
	RequestorSettingsScopeTypeSpecificConnectedOrganizationSubjects      RequestorSettingsScopeType = "SpecificConnectedOrganizationSubjects"
	RequestorSettingsScopeTypeSpecificDirectorySubjects                  RequestorSettingsScopeType = "SpecificDirectorySubjects"
)

type ResourceAccessType = string

const (
	ResourceAccessTypeRole  ResourceAccessType = "Role"
	ResourceAccessTypeScope ResourceAccessType = "Scope"
)

type SchemaExtensionStatus = string

const (
	SchemaExtensionStatusInDevelopment SchemaExtensionStatus = "InDevelopment"
	SchemaExtensionStatusAvailable     SchemaExtensionStatus = "Available"
	SchemaExtensionStatusDeprecated    SchemaExtensionStatus = "Deprecated"
)

type SchemaExtensionProperties interface {
	UnmarshalJSON([]byte) error
}

type SchemaExtensionMap map[string]interface{}

func (m *SchemaExtensionMap) UnmarshalJSON(data []byte) error {
	type sem SchemaExtensionMap
	m2 := (*sem)(m)
	return json.Unmarshal(data, m2)
}

type SignInAudience = string

const (
	SignInAudienceAzureADMyOrg                       SignInAudience = "AzureADMyOrg"
	SignInAudienceAzureADMultipleOrgs                SignInAudience = "AzureADMultipleOrgs"
	SignInAudienceAzureADandPersonalMicrosoftAccount SignInAudience = "AzureADandPersonalMicrosoftAccount"
	SignInAudiencePersonalMicrosoftAccount           SignInAudience = "PersonalMicrosoftAccount"
)

type UsageAuthMethod = string

const (
	UsageAuthMethodEmail                 UsageAuthMethod = "email"
	UsageAuthMethodMobileSMS             UsageAuthMethod = "mobileSMS"
	UsageAuthMethodMobileCall            UsageAuthMethod = "mobileCall"
	UsageAuthMethodOfficePhone           UsageAuthMethod = "officePhone"
	UsageAuthMethodSecurityQuestion      UsageAuthMethod = "securityQuestion"
	UsageAuthMethodAppNotification       UsageAuthMethod = "appNotification"
	UsageAuthMethodAppCode               UsageAuthMethod = "appCode"
	UsageAuthMethodAlternativeMobileCall UsageAuthMethod = "alternateMobileCall"
	UsageAuthMethodFido                  UsageAuthMethod = "fido"
	UsageAuthMethodAppPassword           UsageAuthMethod = "appPassword"
	UsageAuthMethodUnknownFutureValue    UsageAuthMethod = "unknownFutureValue"
)

type IncludedUserRoles = string

const (
	IncludedUserRolesAll             IncludedUserRoles = "all"
	IncludedUserRolesPrivilegedAdmin IncludedUserRoles = "privilegedAdmin"
	IncludedUserRolesAdmin           IncludedUserRoles = "admin"
	IncludedUserRolesUser            IncludedUserRoles = "user"
)

type IncludedUserTypes = string

const (
	IncludedUserTypesAll    IncludedUserTypes = "all"
	IncludedUserTypesMember IncludedUserTypes = "member"
	IncludedUserTypesGuest  IncludedUserTypes = "guest"
)

type DeviceManagementConfigurationPlatforms = string

const (
	DeviceManagementConfigurationPlatformsNone               DeviceManagementConfigurationPlatforms = "none"
	DeviceManagementConfigurationPlatformsAndroid            DeviceManagementConfigurationPlatforms = "android"
	DeviceManagementConfigurationPlatformsIOS                DeviceManagementConfigurationPlatforms = "iOS"
	DeviceManagementConfigurationPlatformsMacOS              DeviceManagementConfigurationPlatforms = "macOS"
	DeviceManagementConfigurationPlatformsWindows10X         DeviceManagementConfigurationPlatforms = "windows10X"
	DeviceManagementConfigurationPlatformsWindows10          DeviceManagementConfigurationPlatforms = "windows10"
	DeviceManagementConfigurationPlatformsLinux              DeviceManagementConfigurationPlatforms = "linux"
	DeviceManagementConfigurationPlatformsUnknownFutureValue DeviceManagementConfigurationPlatforms = "unknownFutureValue"
)

type DeviceManagementConfigurationTechnologies = string

const (
	DeviceManagementConfigurationTechnologiesNone                 DeviceManagementConfigurationTechnologies = "none"
	DeviceManagementConfigurationTechnologiesMdm                  DeviceManagementConfigurationTechnologies = "mdm"
	DeviceManagementConfigurationTechnologiesWindows10XManagement DeviceManagementConfigurationTechnologies = "windows10XManagement"
	DeviceManagementConfigurationTechnologiesConfigManager        DeviceManagementConfigurationTechnologies = "configManager"
	DeviceManagementConfigurationTechnologiesMicrosoftSense       DeviceManagementConfigurationTechnologies = "microsoftSense"
	DeviceManagementConfigurationTechnologiesExchangeOnline       DeviceManagementConfigurationTechnologies = "exchangeOnline"
	DeviceManagementConfigurationTechnologiesLinuxMdm             DeviceManagementConfigurationTechnologies = "linuxMdm"
	DeviceManagementConfigurationTechnologiesUnknownFutureValue   DeviceManagementConfigurationTechnologies = "unknownFutureValue"
)

type WindowsDefenderProductStatus = string

const (
	WindowsDefenderProductStatusNoStatus                                        WindowsDefenderProductStatus = "noStatus"
	WindowsDefenderProductStatusServiceNotRunning                               WindowsDefenderProductStatus = "serviceNotRunning"
	WindowsDefenderProductStatusServiceStartedWithoutMalwareProtection          WindowsDefenderProductStatus = "serviceStartedWithoutMalwareProtection"
	WindowsDefenderProductStatusPendingFullScanDueToThreatAction                WindowsDefenderProductStatus = "pendingFullScanDueToThreatAction"
	WindowsDefenderProductStatusPendingRebootDueToThreatAction                  WindowsDefenderProductStatus = "pendingRebootDueToThreatAction"
	WindowsDefenderProductStatusPendingManualStepsDueToThreatAction             WindowsDefenderProductStatus = "pendingManualStepsDueToThreatAction"
	WindowsDefenderProductStatusAvSignaturesOutOfDate                           WindowsDefenderProductStatus = "avSignaturesOutOfDate"
	WindowsDefenderProductStatusAsSignaturesOutOfDate                           WindowsDefenderProductStatus = "asSignaturesOutOfDate"
	WindowsDefenderProductStatusNoQuickScanHappenedForSpecifiedPeriod           WindowsDefenderProductStatus = "noQuickScanHappenedForSpecifiedPeriod"
	WindowsDefenderProductStatusNoFullScanHappenedForSpecifiedPeriod            WindowsDefenderProductStatus = "noFullScanHappenedForSpecifiedPeriod"
	WindowsDefenderProductStatusSystemInitiatedScanInProgress                   WindowsDefenderProductStatus = "systemInitiatedScanInProgress"
	WindowsDefenderProductStatusSystemInitiatedCleanInProgress                  WindowsDefenderProductStatus = "systemInitiatedCleanInProgress"
	WindowsDefenderProductStatusSamplesPendingSubmission                        WindowsDefenderProductStatus = "samplesPendingSubmission"
	WindowsDefenderProductStatusProductRunningInEvaluationMode                  WindowsDefenderProductStatus = "productRunningInEvaluationMode"
	WindowsDefenderProductStatusProductRunningInNonGenuineMode                  WindowsDefenderProductStatus = "productRunningInNonGenuineMode"
	WindowsDefenderProductStatusProductExpired                                  WindowsDefenderProductStatus = "productExpired"
	WindowsDefenderProductStatusOfflineScanRequired                             WindowsDefenderProductStatus = "offlineScanRequired"
	WindowsDefenderProductStatusServiceShutdownAsPartOfSystemShutdown           WindowsDefenderProductStatus = "serviceShutdownAsPartOfSystemShutdown"
	WindowsDefenderProductStatusThreatRemediationFailedCritically               WindowsDefenderProductStatus = "threatRemediationFailedCritically"
	WindowsDefenderProductStatusThreatRemediationFailedNonCritically            WindowsDefenderProductStatus = "threatRemediationFailedNonCritically"
	WindowsDefenderProductStatusNoStatusFlagsSet                                WindowsDefenderProductStatus = "noStatusFlagsSet"
	WindowsDefenderProductStatusPlatformOutOfDate                               WindowsDefenderProductStatus = "platformOutOfDate"
	WindowsDefenderProductStatusPlatformUpdateInProgress                        WindowsDefenderProductStatus = "platformUpdateInProgress"
	WindowsDefenderProductStatusPlatformAboutToBeOutdated                       WindowsDefenderProductStatus = "platformAboutToBeOutdated"
	WindowsDefenderProductStatusSignatureOrPlatformEndOfLifeIsPastOrIsImpending WindowsDefenderProductStatus = "signatureOrPlatformEndOfLifeIsPastOrIsImpending"
	WindowsDefenderProductStatusWindowsSModeSignaturesInUseOnNonWin10SInstall   WindowsDefenderProductStatus = "windowsSModeSignaturesInUseOnNonWin10SInstall"
)

type WindowsDeviceHealthState = string

const (
	WindowsDeviceHealthStateClean              WindowsDeviceHealthState = "clean"
	WindowsDeviceHealthStateFullScanPending    WindowsDeviceHealthState = "fullScanPending"
	WindowsDeviceHealthStateRebootPending      WindowsDeviceHealthState = "rebootPending"
	WindowsDeviceHealthStateManualStepsPending WindowsDeviceHealthState = "manualStepsPending"
	WindowsDeviceHealthStateOfflineScanPending WindowsDeviceHealthState = "offlineScanPending"
	WindowsDeviceHealthStateCritical           WindowsDeviceHealthState = "critical"
)

type RequiredPasswordType = string

const (
	RequiredPasswordTypeDeviceDefault RequiredPasswordType = "deviceDefault"
	RequiredPasswordTypeAlphanumeric  RequiredPasswordType = "alphanumeric"
	RequiredPasswordTypeNumeric       RequiredPasswordType = "numeric"
)

type DeviceThreatProtectionLevel = string

const (
	DeviceThreatProtectionLevelUnavailable DeviceThreatProtectionLevel = "unavailable"
	DeviceThreatProtectionLevelSecured     DeviceThreatProtectionLevel = "secured"
	DeviceThreatProtectionLevelLow         DeviceThreatProtectionLevel = "low"
	DeviceThreatProtectionLevelMedium      DeviceThreatProtectionLevel = "medium"
	DeviceThreatProtectionLevelHigh        DeviceThreatProtectionLevel = "high"
	DeviceThreatProtectionLevelNotSet      DeviceThreatProtectionLevel = "notSet"
)

type DeviceAndAppManagementAssignmentSource = string

const (
	DeviceAndAppManagementAssignmentSourceDirect     DeviceAndAppManagementAssignmentSource = "direct"
	DeviceAndAppManagementAssignmentSourcePolicySets DeviceAndAppManagementAssignmentSource = "policySets"
)

type DeviceAndAppManagementAssignmentFilterType = string

const (
	DeviceAndAppManagementAssignmentFilterTypeNone    DeviceAndAppManagementAssignmentFilterType = "none"
	DeviceAndAppManagementAssignmentFilterTypeInclude DeviceAndAppManagementAssignmentFilterType = "include"
	DeviceAndAppManagementAssignmentFilterTypeExclude DeviceAndAppManagementAssignmentFilterType = "exclude"
)

type DeviceComplianceActionType = string

const (
	DeviceComplianceActionTypeNoAction                     DeviceComplianceActionType = "noAction"
	DeviceComplianceActionTypeNotification                 DeviceComplianceActionType = "notification"
	DeviceComplianceActionTypeBlock                        DeviceComplianceActionType = "block"
	DeviceComplianceActionTypeRetire                       DeviceComplianceActionType = "retire"
	DeviceComplianceActionTypeWipe                         DeviceComplianceActionType = "wipe"
	DeviceComplianceActionTypeRemoveResourceAccessProfiles DeviceComplianceActionType = "removeResourceAccessProfiles"
	DeviceComplianceActionTypePushNotification             DeviceComplianceActionType = "pushNotification"
	DeviceComplianceActionTypeRemoteLock                   DeviceComplianceActionType = "remoteLock"
)

type DeviceManagementConfigurationTemplateFamily = string

const (
	DeviceManagementConfigurationTemplateFamilyNone                                         DeviceManagementConfigurationTemplateFamily = "none"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityAntivirus                    DeviceManagementConfigurationTemplateFamily = "endpointSecurityAntivirus"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityDiskEncryption               DeviceManagementConfigurationTemplateFamily = "endpointSecurityDiskEncryption"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityFirewall                     DeviceManagementConfigurationTemplateFamily = "endpointSecurityFirewall"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityEndpointDetectionAndResponse DeviceManagementConfigurationTemplateFamily = "endpointSecurityEndpointDetectionAndResponse"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityAttackSurfaceReduction       DeviceManagementConfigurationTemplateFamily = "endpointSecurityAttackSurfaceReduction"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityAccountProtection            DeviceManagementConfigurationTemplateFamily = "endpointSecurityAccountProtection"
	DeviceManagementConfigurationTemplateFamilyEndpointSecurityApplicationControl           DeviceManagementConfigurationTemplateFamily = "endpointSecurityApplicationControl"
	DeviceManagementConfigurationTemplateFamilyBaseline                                     DeviceManagementConfigurationTemplateFamily = "baseline"
)

type ChassisType = string

const (
	ChassisTypeUnknown          ChassisType = "unknown"
	ChassisTypeDesktop          ChassisType = "desktop"
	ChassisTypeLaptop           ChassisType = "laptop"
	ChassisTypeWorksWorkstation ChassisType = "worksWorkstation"
	ChassisTypeEnterpriseServer ChassisType = "enterpriseServer"
	ChassisTypePhone            ChassisType = "phone"
	ChassisTypeTablet           ChassisType = "tablet"
	ChassisTypeMobileOther      ChassisType = "mobileOther"
	ChassisTypeMobileUnknown    ChassisType = "mobileUnknown"
)

type ComplianceState = string

const (
	ComplianceStateUnknown       ComplianceState = "unknown"
	ComplianceStateCompliant     ComplianceState = "compliant"
	ComplianceStateNoncompliant  ComplianceState = "noncompliant"
	ComplianceStateConflict      ComplianceState = "conflict"
	ComplianceStateError         ComplianceState = "error"
	ComplianceStateInGracePeriod ComplianceState = "inGracePeriod"
	ComplianceStateConfigManager ComplianceState = "configManager"
)

type ConfigurationManagerClientState = string

const (
	ConfigurationManagerClientStateUnknown            ConfigurationManagerClientState = "unknown"
	ConfigurationManagerClientStateInstalled          ConfigurationManagerClientState = "installed"
	ConfigurationManagerClientStateHealthy            ConfigurationManagerClientState = "healthy"
	ConfigurationManagerClientStateInstallFailed      ConfigurationManagerClientState = "installFailed"
	ConfigurationManagerClientStateUpdateFailed       ConfigurationManagerClientState = "updateFailed"
	ConfigurationManagerClientStateCommunicationError ConfigurationManagerClientState = "communicationError"
)

type ActionState = string

const (
	ActionStateNone         ActionState = "none"
	ActionStatePending      ActionState = "pending"
	ActionStateCanceled     ActionState = "canceled"
	ActionStateActive       ActionState = "active"
	ActionStateDone         ActionState = "done"
	ActionStateFailed       ActionState = "failed"
	ActionStateNotSupported ActionState = "notSupported"
)

type DeviceEnrollmentType = string

const (
	DeviceEnrollmentTypeUnknown                               DeviceEnrollmentType = "unknown"
	DeviceEnrollmentTypeUserEnrollment                        DeviceEnrollmentType = "userEnrollment"
	DeviceEnrollmentTypeDeviceEnrollmentManager               DeviceEnrollmentType = "deviceEnrollmentManager"
	DeviceEnrollmentTypeAppleBulkWithUser                     DeviceEnrollmentType = "appleBulkWithUser"
	DeviceEnrollmentTypeAppleBulkWithoutUser                  DeviceEnrollmentType = "appleBulkWithoutUser"
	DeviceEnrollmentTypeWindowsAzureADJoin                    DeviceEnrollmentType = "windowsAzureADJoin"
	DeviceEnrollmentTypeWindowsBulkUserless                   DeviceEnrollmentType = "windowsBulkUserless"
	DeviceEnrollmentTypeWindowsAutoEnrollment                 DeviceEnrollmentType = "windowsAutoEnrollment"
	DeviceEnrollmentTypeWindowsBulkAzureDomainJoin            DeviceEnrollmentType = "windowsBulkAzureDomainJoin"
	DeviceEnrollmentTypeWindowsCoManagement                   DeviceEnrollmentType = "windowsCoManagement"
	DeviceEnrollmentTypeWindowsAzureADJoinUsingDeviceAuth     DeviceEnrollmentType = "windowsAzureADJoinUsingDeviceAuth"
	DeviceEnrollmentTypeAppleUserEnrollment                   DeviceEnrollmentType = "appleUserEnrollment"
	DeviceEnrollmentTypeAppleUserEnrollmentWithServiceAccount DeviceEnrollmentType = "appleUserEnrollmentWithServiceAccount"
	DeviceEnrollmentTypeAzureAdJoinUsingAzureVmExtension      DeviceEnrollmentType = "azureAdJoinUsingAzureVmExtension"
	DeviceEnrollmentTypeAndroidEnterpriseDedicatedDevice      DeviceEnrollmentType = "androidEnterpriseDedicatedDevice"
	DeviceEnrollmentTypeAndroidEnterpriseFullyManaged         DeviceEnrollmentType = "androidEnterpriseFullyManaged"
	DeviceEnrollmentTypeAndroidEnterpriseCorporateWorkProfile DeviceEnrollmentType = "androidEnterpriseCorporateWorkProfile"
)

type DeviceGuardLocalSystemAuthorityCredentialGuardState = string

const (
	DeviceGuardLocalSystemAuthorityCredentialGuardStateRunning                               DeviceGuardLocalSystemAuthorityCredentialGuardState = "running"
	DeviceGuardLocalSystemAuthorityCredentialGuardStateRebootRequired                        DeviceGuardLocalSystemAuthorityCredentialGuardState = "rebootRequired"
	DeviceGuardLocalSystemAuthorityCredentialGuardStateNotLicensed                           DeviceGuardLocalSystemAuthorityCredentialGuardState = "notLicensed"
	DeviceGuardLocalSystemAuthorityCredentialGuardStateNotConfigured                         DeviceGuardLocalSystemAuthorityCredentialGuardState = "notConfigured"
	DeviceGuardLocalSystemAuthorityCredentialGuardStateVirtualizationBasedSecurityNotRunning DeviceGuardLocalSystemAuthorityCredentialGuardState = "virtualizationBasedSecurityNotRunning"
)

type DeviceRegistrationState = string

const (
	DeviceRegistrationStateNotRegistered                  DeviceRegistrationState = "notRegistered"
	DeviceRegistrationStateRegistered                     DeviceRegistrationState = "registered"
	DeviceRegistrationStateRevoked                        DeviceRegistrationState = "revoked"
	DeviceRegistrationStateKeyConflict                    DeviceRegistrationState = "keyConflict"
	DeviceRegistrationStateApprovalPending                DeviceRegistrationState = "approvalPending"
	DeviceRegistrationStateCertificateReset               DeviceRegistrationState = "certificateReset"
	DeviceRegistrationStateNotRegisteredPendingEnrollment DeviceRegistrationState = "notRegisteredPendingEnrollment"
	DeviceRegistrationStateUnknown                        DeviceRegistrationState = "unknown"
)

type DeviceType = string

const (
	DeviceTypeDesktop           DeviceType = "desktop"
	DeviceTypeWindowsRT         DeviceType = "windowsRT"
	DeviceTypeWinMO6            DeviceType = "winMO6"
	DeviceTypeNokia             DeviceType = "nokia"
	DeviceTypeWindowsPhone      DeviceType = "windowsPhone"
	DeviceTypeMac               DeviceType = "mac"
	DeviceTypeWinCE             DeviceType = "winCE"
	DeviceTypeWinEmbedded       DeviceType = "winEmbedded"
	DeviceTypeIPhone            DeviceType = "iPhone"
	DeviceTypeIPad              DeviceType = "iPad"
	DeviceTypeIPod              DeviceType = "iPod"
	DeviceTypeAndroid           DeviceType = "android"
	DeviceTypeISocConsumer      DeviceType = "iSocConsumer"
	DeviceTypeUnix              DeviceType = "unix"
	DeviceTypeMacMDM            DeviceType = "macMDM"
	DeviceTypeHoloLens          DeviceType = "holoLens"
	DeviceTypeSurfaceHub        DeviceType = "surfaceHub"
	DeviceTypeAndroidForWork    DeviceType = "androidForWork"
	DeviceTypeAndroidEnterprise DeviceType = "androidEnterprise"
	DeviceTypeWindows10X        DeviceType = "windows10x"
	DeviceTypeAndroidnGMS       DeviceType = "androidnGMS"
	DeviceTypeChromeOS          DeviceType = "chromeOS"
	DeviceTypeLinux             DeviceType = "linux"
	DeviceTypeBlackberry        DeviceType = "blackberry"
	DeviceTypePalm              DeviceType = "palm"
	DeviceTypeUnknown           DeviceType = "unknown"
	DeviceTypeCloudPC           DeviceType = "cloudPC"
)

type DeviceManagementExchangeAccessStateReason = string

const (
	DeviceManagementExchangeAccessStateReasonNone                          DeviceManagementExchangeAccessStateReason = "none"
	DeviceManagementExchangeAccessStateReasonUnknown                       DeviceManagementExchangeAccessStateReason = "unknown"
	DeviceManagementExchangeAccessStateReasonExchangeGlobalRule            DeviceManagementExchangeAccessStateReason = "exchangeGlobalRule"
	DeviceManagementExchangeAccessStateReasonExchangeIndividualRule        DeviceManagementExchangeAccessStateReason = "exchangeIndividualRule"
	DeviceManagementExchangeAccessStateReasonExchangeDeviceRule            DeviceManagementExchangeAccessStateReason = "exchangeDeviceRule"
	DeviceManagementExchangeAccessStateReasonExchangeUpgrade               DeviceManagementExchangeAccessStateReason = "exchangeUpgrade"
	DeviceManagementExchangeAccessStateReasonExchangeMailboxPolicy         DeviceManagementExchangeAccessStateReason = "exchangeMailboxPolicy"
	DeviceManagementExchangeAccessStateReasonOther                         DeviceManagementExchangeAccessStateReason = "other"
	DeviceManagementExchangeAccessStateReasonCompliant                     DeviceManagementExchangeAccessStateReason = "compliant"
	DeviceManagementExchangeAccessStateReasonNotCompliant                  DeviceManagementExchangeAccessStateReason = "notCompliant"
	DeviceManagementExchangeAccessStateReasonNotEnrolled                   DeviceManagementExchangeAccessStateReason = "notEnrolled"
	DeviceManagementExchangeAccessStateReasonUnknownLocation               DeviceManagementExchangeAccessStateReason = "unknownLocation"
	DeviceManagementExchangeAccessStateReasonMfaRequired                   DeviceManagementExchangeAccessStateReason = "mfaRequired"
	DeviceManagementExchangeAccessStateReasonAzureADBlockDueToAccessPolicy DeviceManagementExchangeAccessStateReason = "azureADBlockDueToAccessPolicy"
	DeviceManagementExchangeAccessStateReasonCompromisedPassword           DeviceManagementExchangeAccessStateReason = "compromisedPassword"
	DeviceManagementExchangeAccessStateReasonDeviceNotKnownWithManagedApp  DeviceManagementExchangeAccessStateReason = "deviceNotKnownWithManagedApp"
)

type DeviceManagementExchangeAccessState = string

const (
	DeviceManagementExchangeAccessStateNone        DeviceManagementExchangeAccessState = "none"
	DeviceManagementExchangeAccessStateUnknown     DeviceManagementExchangeAccessState = "unknown"
	DeviceManagementExchangeAccessStateAllowed     DeviceManagementExchangeAccessState = "allowed"
	DeviceManagementExchangeAccessStateBlocked     DeviceManagementExchangeAccessState = "blocked"
	DeviceManagementExchangeAccessStateQuarantined DeviceManagementExchangeAccessState = "quarantined"
)

type JoinType = string

const (
	JoinTypeUnknown             JoinType = "unknown"
	JoinTypeAzureADJoined       JoinType = "azureADJoined"
	JoinTypeAzureADRegistered   JoinType = "azureADRegistered"
	JoinTypeHybridAzureADJoined JoinType = "hybridAzureADJoined"
)

type LostModeState = string

const (
	LostModeStateDisabled LostModeState = "disabled"
	LostModeStateEnabled  LostModeState = "enabled"
)

type ManagedDeviceOwnerType = string

const (
	ManagedDeviceOwnerTypeUnknown  ManagedDeviceOwnerType = "unknown"
	ManagedDeviceOwnerTypeCompany  ManagedDeviceOwnerType = "company"
	ManagedDeviceOwnerTypePersonal ManagedDeviceOwnerType = "personal"
)

type OwnerType = string

const (
	OwnerTypeUnknown  OwnerType = "unknown"
	OwnerTypeCompany  OwnerType = "company"
	OwnerTypePersonal OwnerType = "personal"
)

type ManagementAgentType = string

const (
	ManagementAgentTypeEas                               ManagementAgentType = "eas"
	ManagementAgentTypeMdm                               ManagementAgentType = "mdm"
	ManagementAgentTypeEasMdm                            ManagementAgentType = "easMdm"
	ManagementAgentTypeIntuneClient                      ManagementAgentType = "intuneClient"
	ManagementAgentTypeEasIntuneClient                   ManagementAgentType = "easIntuneClient"
	ManagementAgentTypeConfigurationManagerClient        ManagementAgentType = "configurationManagerClient"
	ManagementAgentTypeConfigurationManagerClientMdm     ManagementAgentType = "configurationManagerClientMdm"
	ManagementAgentTypeConfigurationManagerClientMdmEas  ManagementAgentType = "configurationManagerClientMdmEas"
	ManagementAgentTypeUnknown                           ManagementAgentType = "unknown"
	ManagementAgentTypeJamf                              ManagementAgentType = "jamf"
	ManagementAgentTypeGoogleCloudDevicePolicyController ManagementAgentType = "googleCloudDevicePolicyController"
	ManagementAgentTypeMicrosoft365ManagedMdm            ManagementAgentType = "microsoft365ManagedMdm"
	ManagementAgentTypeMsSense                           ManagementAgentType = "msSense"
	ManagementAgentTypeIntuneAosp                        ManagementAgentType = "intuneAosp"
)

type ManagedDeviceManagementFeatures = string

const (
	ManagedDeviceManagementFeaturesNone                    ManagedDeviceManagementFeatures = "none"
	ManagedDeviceManagementFeaturesMicrosoftManagedDesktop ManagedDeviceManagementFeatures = "microsoftManagedDesktop"
)

type ManagementState = string

const (
	ManagementStateManaged        ManagementState = "managed"
	ManagementStateRetirePending  ManagementState = "retirePending"
	ManagementStateRetireFailed   ManagementState = "retireFailed"
	ManagementStateWipePending    ManagementState = "wipePending"
	ManagementStateWipeFailed     ManagementState = "wipeFailed"
	ManagementStateUnhealthy      ManagementState = "unhealthy"
	ManagementStateDeletePending  ManagementState = "deletePending"
	ManagementStateRetireIssued   ManagementState = "retireIssued"
	ManagementStateWipeIssued     ManagementState = "wipeIssued"
	ManagementStateWipeCanceled   ManagementState = "wipeCanceled"
	ManagementStateRetireCanceled ManagementState = "retireCanceled"
	ManagementStateDiscovered     ManagementState = "discovered"
)

type ManagedDevicePartnerReportedHealthState = string

const (
	ManagedDevicePartnerReportedHealthStateUnknown        ManagedDevicePartnerReportedHealthState = "unknown"
	ManagedDevicePartnerReportedHealthStateActivated      ManagedDevicePartnerReportedHealthState = "activated"
	ManagedDevicePartnerReportedHealthStateDeactivated    ManagedDevicePartnerReportedHealthState = "deactivated"
	ManagedDevicePartnerReportedHealthStateSecured        ManagedDevicePartnerReportedHealthState = "secured"
	ManagedDevicePartnerReportedHealthStateLowSeverity    ManagedDevicePartnerReportedHealthState = "lowSeverity"
	ManagedDevicePartnerReportedHealthStateMediumSeverity ManagedDevicePartnerReportedHealthState = "mediumSeverity"
	ManagedDevicePartnerReportedHealthStateHighSeverity   ManagedDevicePartnerReportedHealthState = "highSeverity"
	ManagedDevicePartnerReportedHealthStateUnresponsive   ManagedDevicePartnerReportedHealthState = "unresponsive"
	ManagedDevicePartnerReportedHealthStateCompromised    ManagedDevicePartnerReportedHealthState = "compromised"
	ManagedDevicePartnerReportedHealthStateMisconfigured  ManagedDevicePartnerReportedHealthState = "misconfigured"
)

type ManagedDeviceArchitecture = string

const (
	ManagedDeviceArchitectureUnknown ManagedDeviceArchitecture = "unknown"
	ManagedDeviceArchitectureX86     ManagedDeviceArchitecture = "x86"
	ManagedDeviceArchitectureX64     ManagedDeviceArchitecture = "x64"
	ManagedDeviceArchitectureArm     ManagedDeviceArchitecture = "arm"
	ManagedDeviceArchitectureArM64   ManagedDeviceArchitecture = "arM64"
)

type DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = string

const (
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementStateMeetHardwareRequirements     DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "meetHardwareRequirements"
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementStateSecureBootRequired           DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "secureBootRequired"
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementStateDmaProtectionRequired        DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "dmaProtectionRequired"
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementStateHyperVNotSupportedForGuestVM DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "hyperVNotSupportedForGuestVM"
	DeviceGuardVirtualizationBasedSecurityHardwareRequirementStateHyperVNotAvailable           DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "hyperVNotAvailable"
)

type DeviceGuardVirtualizationBasedSecurityState = string

const (
	DeviceGuardVirtualizationBasedSecurityStateRunning                         DeviceGuardVirtualizationBasedSecurityState = "running"
	DeviceGuardVirtualizationBasedSecurityStateRebootRequired                  DeviceGuardVirtualizationBasedSecurityState = "rebootRequired"
	DeviceGuardVirtualizationBasedSecurityStateRequire64BitArchitecture        DeviceGuardVirtualizationBasedSecurityState = "require64BitArchitecture"
	DeviceGuardVirtualizationBasedSecurityStateNotLicensed                     DeviceGuardVirtualizationBasedSecurityState = "notLicensed"
	DeviceGuardVirtualizationBasedSecurityStateNotConfigured                   DeviceGuardVirtualizationBasedSecurityState = "notConfigured"
	DeviceGuardVirtualizationBasedSecurityStateDoesNotMeetHardwareRequirements DeviceGuardVirtualizationBasedSecurityState = "doesNotMeetHardwareRequirements"
	DeviceGuardVirtualizationBasedSecurityStateOther                           DeviceGuardVirtualizationBasedSecurityState = "other"
)

type DefenderPromptForSampleSubmission = string

const (
	DefenderPromptForSampleSubmissionUserDefined                     DefenderPromptForSampleSubmission = "userDefined"
	DefenderPromptForSampleSubmissionAlwaysPrompt                    DefenderPromptForSampleSubmission = "alwaysPrompt"
	DefenderPromptForSampleSubmissionPromptBeforeSendingPersonalData DefenderPromptForSampleSubmission = "promptBeforeSendingPersonalData"
	DefenderPromptForSampleSubmissionNeverSendData                   DefenderPromptForSampleSubmission = "neverSendData"
	DefenderPromptForSampleSubmissionSendAllDataWithoutPrompting     DefenderPromptForSampleSubmission = "sendAllDataWithoutPrompting"
)

type PowerActionType = string

const (
	PowerActionTypeNotConfigured PowerActionType = "notConfigured"
	PowerActionTypeNoAction      PowerActionType = "noAction"
	PowerActionTypeSleep         PowerActionType = "sleep"
	PowerActionTypeHibernate     PowerActionType = "hibernate"
	PowerActionTypeShutdown      PowerActionType = "shutdown"
)

type Windows10AppsUpdateRecurrence = string

const (
	Windows10AppsUpdateRecurrenceNone    Windows10AppsUpdateRecurrence = "none"
	Windows10AppsUpdateRecurrenceDaily   Windows10AppsUpdateRecurrence = "daily"
	Windows10AppsUpdateRecurrenceWeekly  Windows10AppsUpdateRecurrence = "weekly"
	Windows10AppsUpdateRecurrenceMonthly Windows10AppsUpdateRecurrence = "monthly"
)

type EdgeKioskModeRestrictionType = string

const (
	EdgeKioskModeRestrictionTypeNotConfigured           EdgeKioskModeRestrictionType = "notConfigured"
	EdgeKioskModeRestrictionTypeDigitalSignage          EdgeKioskModeRestrictionType = "digitalSignage"
	EdgeKioskModeRestrictionTypeNormalMode              EdgeKioskModeRestrictionType = "normalMode"
	EdgeKioskModeRestrictionTypePublicBrowsingSingleApp EdgeKioskModeRestrictionType = "publicBrowsingSingleApp"
	EdgeKioskModeRestrictionTypePublicBrowsingMultiApp  EdgeKioskModeRestrictionType = "publicBrowsingMultiApp"
)

type DefenderMonitorFileActivity = string

const (
	DefenderMonitorFileActivityUserDefined              DefenderMonitorFileActivity = "userDefined"
	DefenderMonitorFileActivityDisable                  DefenderMonitorFileActivity = "disable"
	DefenderMonitorFileActivityMonitorAllFiles          DefenderMonitorFileActivity = "monitorAllFiles"
	DefenderMonitorFileActivityMonitorIncomingFilesOnly DefenderMonitorFileActivity = "monitorIncomingFilesOnly"
	DefenderMonitorFileActivityMonitorOutgoingFilesOnly DefenderMonitorFileActivity = "monitorOutgoingFilesOnly"
)

type DefenderThreatAction = string

const (
	DefenderThreatActionDeviceDefault DefenderThreatAction = "deviceDefault"
	DefenderThreatActionClean         DefenderThreatAction = "clean"
	DefenderThreatActionQuarantine    DefenderThreatAction = "quarantine"
	DefenderThreatActionRemove        DefenderThreatAction = "remove"
	DefenderThreatActionAllow         DefenderThreatAction = "allow"
	DefenderThreatActionUserDefined   DefenderThreatAction = "userDefined"
	DefenderThreatActionBlock         DefenderThreatAction = "block"
)

type InternetExplorerMessageSetting = string

const (
	InternetExplorerMessageSettingNotConfigured InternetExplorerMessageSetting = "notConfigured"
	InternetExplorerMessageSettingDisabled      InternetExplorerMessageSetting = "disabled"
	InternetExplorerMessageSettingEnabled       InternetExplorerMessageSetting = "enabled"
	InternetExplorerMessageSettingKeepGoing     InternetExplorerMessageSetting = "keepGoing"
)

type DefenderProtectionType = string

const (
	DefenderProtectionTypeUserDefined   DefenderProtectionType = "userDefined"
	DefenderProtectionTypeEnable        DefenderProtectionType = "enable"
	DefenderProtectionTypeAuditMode     DefenderProtectionType = "auditMode"
	DefenderProtectionTypeWarn          DefenderProtectionType = "warn"
	DefenderProtectionTypeNotConfigured DefenderProtectionType = "notConfigured"
)

type WindowsSpotlightEnablementSettings = string

const (
	WindowsSpotlightEnablementSettingsNotConfigured WindowsSpotlightEnablementSettings = "notConfigured"
	WindowsSpotlightEnablementSettingsDisabled      WindowsSpotlightEnablementSettings = "disabled"
	WindowsSpotlightEnablementSettingsEnabled       WindowsSpotlightEnablementSettings = "enabled"
)

type DefenderCloudBlockLevelType = string

const (
	DefenderCloudBlockLevelTypeNotConfigured DefenderCloudBlockLevelType = "notConfigured"
	DefenderCloudBlockLevelTypeHigh          DefenderCloudBlockLevelType = "high"
	DefenderCloudBlockLevelTypeHighPlus      DefenderCloudBlockLevelType = "highPlus"
	DefenderCloudBlockLevelTypeZeroTolerance DefenderCloudBlockLevelType = "zeroTolerance"
)

type Windows10DeviceModeType = string

const (
	Windows10DeviceModeTypeStandardConfiguration Windows10DeviceModeType = "standardConfiguration"
	Windows10DeviceModeTypeSModeConfiguration    Windows10DeviceModeType = "sModeConfiguration"
)

type Windows10EditionType = string

const (
	Windows10EditionTypeWindows10Enterprise               Windows10EditionType = "windows10Enterprise"
	Windows10EditionTypeWindows10EnterpriseN              Windows10EditionType = "windows10EnterpriseN"
	Windows10EditionTypeWindows10Education                Windows10EditionType = "windows10Education"
	Windows10EditionTypeWindows10EducationN               Windows10EditionType = "windows10EducationN"
	Windows10EditionTypeWindows10MobileEnterprise         Windows10EditionType = "windows10MobileEnterprise"
	Windows10EditionTypeWindows10HolographicEnterprise    Windows10EditionType = "windows10HolographicEnterprise"
	Windows10EditionTypeWindows10Professional             Windows10EditionType = "windows10Professional"
	Windows10EditionTypeWindows10ProfessionalN            Windows10EditionType = "windows10ProfessionalN"
	Windows10EditionTypeWindows10ProfessionalEducation    Windows10EditionType = "windows10ProfessionalEducation"
	Windows10EditionTypeWindows10ProfessionalEducationN   Windows10EditionType = "windows10ProfessionalEducationN"
	Windows10EditionTypeWindows10ProfessionalWorkstation  Windows10EditionType = "windows10ProfessionalWorkstation"
	Windows10EditionTypeWindows10ProfessionalWorkstationN Windows10EditionType = "windows10ProfessionalWorkstationN"
	Windows10EditionTypeNotConfigured                     Windows10EditionType = "notConfigured"
	Windows10EditionTypeWindows10Home                     Windows10EditionType = "windows10Home"
	Windows10EditionTypeWindows10HomeChina                Windows10EditionType = "windows10HomeChina"
	Windows10EditionTypeWindows10HomeN                    Windows10EditionType = "windows10HomeN"
	Windows10EditionTypeWindows10HomeSingleLanguage       Windows10EditionType = "windows10HomeSingleLanguage"
	Windows10EditionTypeWindows10Mobile                   Windows10EditionType = "windows10Mobile"
	Windows10EditionTypeWindows10IoTCore                  Windows10EditionType = "windows10IoTCore"
	Windows10EditionTypeWindows10IoTCoreCommercial        Windows10EditionType = "windows10IoTCoreCommercial"
)

type Enablement = string

const (
	EnablementNotConfigured Enablement = "notConfigured"
	EnablementEnabled       Enablement = "enabled"
	EnablementDisabled      Enablement = "disabled"
)

type BrowserSyncSetting = string

const (
	BrowserSyncSettingNotConfigured           BrowserSyncSetting = "notConfigured"
	BrowserSyncSettingBlockedWithUserOverride BrowserSyncSetting = "blockedWithUserOverride"
	BrowserSyncSettingBlocked                 BrowserSyncSetting = "blocked"
)

type DeviceManagementApplicabilityRuleType = string

const (
	DeviceManagementApplicabilityRuleTypeInclude DeviceManagementApplicabilityRuleType = "include"
	DeviceManagementApplicabilityRuleTypeExclude DeviceManagementApplicabilityRuleType = "exclude"
)

type StateManagementSetting = string

const (
	StateManagementSettingNotConfigured StateManagementSetting = "notConfigured"
	StateManagementSettingBlocked       StateManagementSetting = "blocked"
	StateManagementSettingAllowed       StateManagementSetting = "allowed"
)

type DefenderPotentiallyUnwantedAppAction = string

const (
	DefenderPotentiallyUnwantedAppActionDeviceDefault DefenderPotentiallyUnwantedAppAction = "deviceDefault"
	DefenderPotentiallyUnwantedAppActionBlock         DefenderPotentiallyUnwantedAppAction = "block"
	DefenderPotentiallyUnwantedAppActionAudit         DefenderPotentiallyUnwantedAppAction = "audit"
)

type WeeklySchedule = string

const (
	WeeklyScheduleUserDefined     WeeklySchedule = "userDefined"
	WeeklyScheduleEveryday        WeeklySchedule = "everyday"
	WeeklyScheduleSunday          WeeklySchedule = "sunday"
	WeeklyScheduleMonday          WeeklySchedule = "monday"
	WeeklyScheduleTuesday         WeeklySchedule = "tuesday"
	WeeklyScheduleWednesday       WeeklySchedule = "wednesday"
	WeeklyScheduleThursday        WeeklySchedule = "thursday"
	WeeklyScheduleFriday          WeeklySchedule = "friday"
	WeeklyScheduleSaturday        WeeklySchedule = "saturday"
	WeeklyScheduleNoScheduledScan WeeklySchedule = "noScheduledScan"
)

type EdgeOpenOptions = string

const (
	EdgeOpenOptionsNotConfigured EdgeOpenOptions = "notConfigured"
	EdgeOpenOptionsStartPage     EdgeOpenOptions = "startPage"
	EdgeOpenOptionsNewTabPage    EdgeOpenOptions = "newTabPage"
	EdgeOpenOptionsPreviousPages EdgeOpenOptions = "previousPages"
	EdgeOpenOptionsSpecificPages EdgeOpenOptions = "specificPages"
)

type SafeSearchFilterType = string

const (
	SafeSearchFilterTypeUserDefined SafeSearchFilterType = "userDefined"
	SafeSearchFilterTypeStrict      SafeSearchFilterType = "strict"
	SafeSearchFilterTypeModerate    SafeSearchFilterType = "moderate"
)

type AppInstallControlType = string

const (
	AppInstallControlTypeNotConfigured   AppInstallControlType = "notConfigured"
	AppInstallControlTypeAnywhere        AppInstallControlType = "anywhere"
	AppInstallControlTypeStoreOnly       AppInstallControlType = "storeOnly"
	AppInstallControlTypeRecommendations AppInstallControlType = "recommendations"
	AppInstallControlTypePreferStore     AppInstallControlType = "preferStore"
)

type EdgeTelemetryMode = string

const (
	EdgeTelemetryModeNotConfigured       EdgeTelemetryMode = "notConfigured"
	EdgeTelemetryModeIntranet            EdgeTelemetryMode = "intranet"
	EdgeTelemetryModeInternet            EdgeTelemetryMode = "internet"
	EdgeTelemetryModeIntranetAndInternet EdgeTelemetryMode = "intranetAndInternet"
)

type InkAccessSetting = string

const (
	InkAccessSettingNotConfigured InkAccessSetting = "notConfigured"
	InkAccessSettingEnabled       InkAccessSetting = "enabled"
	InkAccessSettingDisabled      InkAccessSetting = "disabled"
)

type DefenderScanType = string

const (
	DefenderScanTypeUserDefined DefenderScanType = "userDefined"
	DefenderScanTypeDisabled    DefenderScanType = "disabled"
	DefenderScanTypeQuick       DefenderScanType = "quick"
	DefenderScanTypeFull        DefenderScanType = "full"
)

type DiagnosticDataSubmissionMode = string

const (
	DiagnosticDataSubmissionModeUserDefined DiagnosticDataSubmissionMode = "userDefined"
	DiagnosticDataSubmissionModeNone        DiagnosticDataSubmissionMode = "none"
	DiagnosticDataSubmissionModeBasic       DiagnosticDataSubmissionMode = "basic"
	DiagnosticDataSubmissionModeEnhanced    DiagnosticDataSubmissionMode = "enhanced"
	DiagnosticDataSubmissionModeFull        DiagnosticDataSubmissionMode = "full"
)

type DefenderSubmitSamplesConsentType = string

const (
	DefenderSubmitSamplesConsentTypeSendSafeSamplesAutomatically DefenderSubmitSamplesConsentType = "sendSafeSamplesAutomatically"
	DefenderSubmitSamplesConsentTypeAlwaysPrompt                 DefenderSubmitSamplesConsentType = "alwaysPrompt"
	DefenderSubmitSamplesConsentTypeNeverSend                    DefenderSubmitSamplesConsentType = "neverSend"
	DefenderSubmitSamplesConsentTypeSendAllSamplesAutomatically  DefenderSubmitSamplesConsentType = "sendAllSamplesAutomatically"
)

type SignInAssistantOptions = string

const (
	SignInAssistantOptionsNotConfigured SignInAssistantOptions = "notConfigured"
	SignInAssistantOptionsDisabled      SignInAssistantOptions = "disabled"
)

type ConfigurationUsage = string

const (
	ConfigurationUsageBlocked       ConfigurationUsage = "blocked"
	ConfigurationUsageRequired      ConfigurationUsage = "required"
	ConfigurationUsageAllowed       ConfigurationUsage = "allowed"
	ConfigurationUsageNotConfigured ConfigurationUsage = "notConfigured"
)

type EdgeCookiePolicy = string

const (
	EdgeCookiePolicyUserDefined     EdgeCookiePolicy = "userDefined"
	EdgeCookiePolicyAllow           EdgeCookiePolicy = "allow"
	EdgeCookiePolicyBlockThirdParty EdgeCookiePolicy = "blockThirdParty"
	EdgeCookiePolicyBlockAll        EdgeCookiePolicy = "blockAll"
)

type VisibilitySetting = string

const (
	VisibilitySettingNotConfigured VisibilitySetting = "notConfigured"
	VisibilitySettingHide          VisibilitySetting = "hide"
	VisibilitySettingShow          VisibilitySetting = "show"
)

type WindowsStartMenuModeType = string

const (
	WindowsStartMenuModeTypeUserDefined   WindowsStartMenuModeType = "userDefined"
	WindowsStartMenuModeTypeFullScreen    WindowsStartMenuModeType = "fullScreen"
	WindowsStartMenuModeTypeNonFullScreen WindowsStartMenuModeType = "nonFullScreen"
)

type WindowsStartMenuAppListVisibilityType = string

const (
	WindowsStartMenuAppListVisibilityTypeUserDefined        WindowsStartMenuAppListVisibilityType = "userDefined"
	WindowsStartMenuAppListVisibilityTypeCollapse           WindowsStartMenuAppListVisibilityType = "collapse"
	WindowsStartMenuAppListVisibilityTypeRemove             WindowsStartMenuAppListVisibilityType = "remove"
	WindowsStartMenuAppListVisibilityTypeDisableSettingsApp WindowsStartMenuAppListVisibilityType = "disableSettingsApp"
)

type AndroidDeviceOwnerRequiredPasswordType = string

const (
	AndroidDeviceOwnerRequiredPasswordTypeDeviceDefault           AndroidDeviceOwnerRequiredPasswordType = "deviceDefault"
	AndroidDeviceOwnerRequiredPasswordTypeRequired                AndroidDeviceOwnerRequiredPasswordType = "required"
	AndroidDeviceOwnerRequiredPasswordTypeNumeric                 AndroidDeviceOwnerRequiredPasswordType = "numeric"
	AndroidDeviceOwnerRequiredPasswordTypeNumericComplex          AndroidDeviceOwnerRequiredPasswordType = "numericComplex"
	AndroidDeviceOwnerRequiredPasswordTypeAlphabetic              AndroidDeviceOwnerRequiredPasswordType = "alphabetic"
	AndroidDeviceOwnerRequiredPasswordTypeAlphanumeric            AndroidDeviceOwnerRequiredPasswordType = "alphanumeric"
	AndroidDeviceOwnerRequiredPasswordTypeAlphanumericWithSymbols AndroidDeviceOwnerRequiredPasswordType = "alphanumericWithSymbols"
	AndroidDeviceOwnerRequiredPasswordTypeLowSecurityBiometric    AndroidDeviceOwnerRequiredPasswordType = "lowSecurityBiometric"
	AndroidDeviceOwnerRequiredPasswordTypeCustomPassword          AndroidDeviceOwnerRequiredPasswordType = "customPassword"
)

type DeviceManagementConfigurationDeviceMode = string

const (
	DeviceManagementConfigurationDeviceModeNone  DeviceManagementConfigurationDeviceMode = "none"
	DeviceManagementConfigurationDeviceModeKiosk DeviceManagementConfigurationDeviceMode = "kiosk"
)

type DeviceManagementConfigurationSettingUsage = string

const (
	DeviceManagementConfigurationSettingUsageNone          DeviceManagementConfigurationSettingUsage = "none"
	DeviceManagementConfigurationSettingUsageConfiguration DeviceManagementConfigurationSettingUsage = "configuration"
	DeviceManagementConfigurationSettingUsageCompliance    DeviceManagementConfigurationSettingUsage = "compliance"
)

type DeviceManagementConfigurationSettingVisibility = string

const (
	DeviceManagementConfigurationSettingVisibilityNone            DeviceManagementConfigurationSettingVisibility = "none"
	DeviceManagementConfigurationSettingVisibilitySettingsCatalog DeviceManagementConfigurationSettingVisibility = "settingsCatalog"
	DeviceManagementConfigurationSettingVisibilityTemplate        DeviceManagementConfigurationSettingVisibility = "template"
)

type DeviceManagementConfigurationSettingAccessTypes = string

const (
	DeviceManagementConfigurationSettingAccessTypesNone    DeviceManagementConfigurationSettingAccessTypes = "none"
	DeviceManagementConfigurationSettingAccessTypesAdd     DeviceManagementConfigurationSettingAccessTypes = "add"
	DeviceManagementConfigurationSettingAccessTypesCopy    DeviceManagementConfigurationSettingAccessTypes = "copy"
	DeviceManagementConfigurationSettingAccessTypesDelete  DeviceManagementConfigurationSettingAccessTypes = "delete"
	DeviceManagementConfigurationSettingAccessTypesGet     DeviceManagementConfigurationSettingAccessTypes = "get"
	DeviceManagementConfigurationSettingAccessTypesReplace DeviceManagementConfigurationSettingAccessTypes = "replace"
	DeviceManagementConfigurationSettingAccessTypesExecute DeviceManagementConfigurationSettingAccessTypes = "execute"
)

type DeviceManagementConfigurationControlType = string

const (
	DeviceManagementConfigurationControlTypeDefault         DeviceManagementConfigurationControlType = "default"
	DeviceManagementConfigurationControlTypeDropdown        DeviceManagementConfigurationControlType = "dropdown"
	DeviceManagementConfigurationControlTypeSmallTextBox    DeviceManagementConfigurationControlType = "smallTextBox"
	DeviceManagementConfigurationControlTypeLargeTextBox    DeviceManagementConfigurationControlType = "largeTextBox"
	DeviceManagementConfigurationControlTypeToggle          DeviceManagementConfigurationControlType = "toggle"
	DeviceManagementConfigurationControlTypeMultiheaderGrid DeviceManagementConfigurationControlType = "multiheaderGrid"
	DeviceManagementConfigurationControlTypeContextPane     DeviceManagementConfigurationControlType = "contextPane"
)
