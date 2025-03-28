/**
 * This action source is fetched rom the auth0 dashboard.
 */

/**
 *  e.g.:
 *  export type AddonsTypesRegistry = {
 *    "0": { // this key doesn't matter, it's just because TS is very bad at handling arrays so we use a map to iterate over it
 *      id: {
 *        trigger_type: "POST_LOGIN";
 *        trigger_version: "v3";
 *        path": "user.myaddon";
 *        version: "v1";
 *      };
 *       type: addons.user.myaddon.v1;
 *    };
 *  };
 */
type AddonsTypesRegistry = {};

type AddonID = {
  trigger_type: string;
  trigger_version: string;
  path: string;
  version: string;
};
/**
 * GeneratedRegistry is a type that AddonsTypesRegistry must conform to.
 *
 * This registry maps a string key to an object containing an `AddonID` and a type.
 * The type is the name of the add-on that will be merged into the event.
 *
 * @example
 * const registry: GeneratedRegistry = {
 *   "addon1": {
 *     id: {
 *       trigger_type: "POST_LOGIN",
 *       trigger_version: "v3",
 *       path: "user.enrolled_factors",
 *       version: "v1"
 *     },
 *     type: {
 *      id: "user.enrolled_factors",
 *     }
 *   },
 *   "addon2": {
 *     id: {
 *       trigger_type: "PRE_LOGOUT",
 *       trigger_version: "v1",
 *       path: "user.logout",
 *       version: "v2"
 *     },
 *     type: {
 *      id: "user.logout",
 *     }
 *   }
 * };
 */
interface GeneratedRegistry {
  [key: string]: {
    id: AddonID;
    type: unknown;
  };
}
type KebabToSnakeCase<S extends string> = S extends `${infer P}-${infer U}`
  ? `${P}_${KebabToSnakeCase<U>}`
  : S;
type AddonIDToKey<T extends AddonID> = `${Uppercase<
  KebabToSnakeCase<T['trigger_type']>
>}|${T['trigger_version']}|${T['path']}|${T['version']}`;
type Prettify<T> = T extends object
  ? {
      [K in keyof T]: Prettify<T[K]>;
    }
  : T & {};
type UnionToIntersection<U> = (U extends any ? (x: U) => void : never) extends (x: infer I) => void
  ? I
  : never;
type Extend<NS extends string, T extends unknown> = NS extends `${infer P}.${infer U}`
  ? {
      [K in P]: Extend<U, T>;
    }
  : NS extends ''
    ? T
    : {
        [K in NS]: NS extends keyof T ? (Exclude<keyof T, NS> extends never ? T[NS] : T) : T;
      };
type PickValues<T, K> = T[Extract<K, keyof T>];
type ReindexRegistryByKey<Registry extends GeneratedRegistry> = {
  [K in keyof Registry as AddonIDToKey<Registry[K]['id']>]: Extend<
    Registry[K]['id']['path'],
    Registry[K]['type']
  >;
};
type WithAddons<
  Base extends unknown,
  IDs extends AddonID[] | undefined = undefined,
  Registry extends GeneratedRegistry | undefined = undefined,
> = IDs extends AddonID[]
  ? Prettify<
      Base &
        UnionToIntersection<
          {
            [K in keyof IDs]: IDs[K] extends AddonID
              ? PickValues<
                  ReindexRegistryByKey<
                    Registry extends GeneratedRegistry ? Registry : AddonsTypesRegistry
                  >,
                  AddonIDToKey<IDs[K]>
                >
              : never;
          }[number]
        >
    >
  : Base;
type AccessDeniedErrorCode = 'invalid_scope' | 'invalid_request' | 'server_error';
interface InternalCommandAddError {
  type: 'error';
  code: 'MaxSideEffectsExceeded';
}
type SetSAMLAttributeValue = SAMLAttributeValue;
type RenderPromptId = PromptId;
type RenderPromptOptions = PromptOptions;

type CacheWriteErrorCode =
  | InternalCommandAddError['code']
  | 'CacheKeySizeExceeded'
  | 'CacheValueSizeExceeded'
  | 'CacheSizeExceeded'
  | 'ItemAlreadyExpired'
  | 'InvalidExpiry'
  | 'FailedToSetCacheRecord'
  | 'FailedToDeleteCacheRecord'
  | 'CacheKeyDoesNotExist';
/**
 * Details about a cached value.
 */
interface CacheRecord {
  /**
   * The cached value itself.
   */
  value: string;
  /**
   * Expiry time in milliseconds since the unix epoch.
   */
  expires_at: number;
}
interface CacheWriteSuccess {
  type: 'success';
  record: CacheRecord;
}
interface CacheWriteError {
  type: 'error';
  code: CacheWriteErrorCode;
}
type CacheWriteResult = CacheWriteSuccess | CacheWriteError;
interface CacheDeleteSuccess {
  type: 'success';
}
type CacheDeleteResult = CacheDeleteSuccess | CacheWriteError;
interface CacheSetOptions {
  /**
   * The absolute expiry time in milliseconds since the unix epoch.
   * While cached records may be evicted earlier, they will
   * never remain beyond the the supplied `expires_at`.
   *
   * *Note*: This value should not be supplied if a value was also
   * provided for `ttl`. If both options are supplied, the
   * earlier expiry of the two will be used.
   */
  expires_at?: number;
  /**
   * The time-to-live value of this cache entry in milliseconds.
   * While cached values may be evicted earlier, they will
   * never remain beyond the the supplied `ttl`.
   *
   * *Note*: This value should not be supplied if a value was also
   * provided for `expires_at`. If both options are supplied, the
   * earlier expiry of the two will be used.
   */
  ttl?: number;
}
/**
 * Methods and utilities to manage the Actions cache.
 */
interface CacheAPI {
  /**
   * Delete a record describing a cached value at the supplied
   * key if it exists.
   *
   * @param key The key of the cache record to delete.
   */
  delete(key: string): CacheDeleteResult;
  /**
   * Retrieve a record describing a cached value at the supplied key,
   * if it exists. If a record is found, the cached value can be found
   * at the `value` property of the returned object.
   *
   * @param key The key of the record stored in the cache.
   */
  get(key: string): CacheRecord | undefined;
  /**
   * Store or update a string value in the cache at the specified key.
   *
   * Values stored in this cache are scoped to the Trigger in which they
   * are set. They are subject to the {@link https://auth0.com/docs/customize/actions/limitations Actions Cache Limits}.
   *
   * Values stored in this way will have lifetimes of _up to_ the specified
   * `ttl` or `expires_at` values. If no lifetime is specified, a default of
   * lifetime of 24 hours will be used. Lifetimes may not exceed the maximum
   * duration listed at {@link https://auth0.com/docs/customize/actions/limitations Actions Cache Limits}.
   *
   * **Important**: This cache is designed for short-lived, ephemeral data. Items may not be
   * available in later transactions even if they are within their supplied their lifetime.
   *
   * @param key The key of the record to be stored.
   * @param value The value of the record to be stored.
   * @param options Options for adjusting cache behavior.
   */
  set(key: string, value: string, options?: CacheSetOptions): CacheWriteResult;
}
/** AccessToken */
type AccessToken = {
  customClaims: {
    [additionalProperties: string]: any;
  };
  scope: string[];
};
/**
 * AuthenticationInfo
 *
 * Details about authentication signals obtained during the login.
 */
type AuthenticationInfoWithRiskAssessment = {
  /** Contains the authentication methods a user has completed during their session. */
  methods: AuthenticationMethod[];
  riskAssessment?: RiskAssessmentInfo;
};
/** AuthenticationMethod */
type AuthenticationMethod =
  | {
      /**
       * The name of the first factor that was completed. Values include the following:
       * - `"federated"` A social or enterprise connection was used to authenticate the user as the first factor.
       * - `"pwd"` A password was used to authenticate a database connection user as the first factor.
       * - `"passkey"` A passkey was used to authenticate a database connnection user as the first factor.
       * - `"sms"` A Passwordless SMS connection was used to authenticate the user as the first factor.
       * - `"email"` A Passwordless Email connection was used to authenticate the user as the first factor or verify email for password reset.
       * - `"phone_number"` A phone number was used for password reset.
       * - `"mock"` Used for internal testing.
       * - `string` A custom authentication method denoted by a URL (as second or later factor).
       */
      name: string;
      timestamp: string;
    }
  | {
      /** The user completed multi-factor authentication (second or later factors). */
      name: 'mfa';
      timestamp: string;
    };
/**
 * AuthorizationInfo
 *
 * An object containing information describing the authorization granted to the user who is logging in.
 */
type AuthorizationInfo = {
  /** An array containing the names of a user's assigned roles. */
  roles: string[];
};
/**
 * Client
 *
 * Information about the Client with which this login transaction was initiated.
 */
type Client = {
  /** The client id of the application the user is logging in to. */
  client_id: string;
  /** The name of the application (as defined in the Dashboard). */
  name: string;
  /** An object for holding other application properties. */
  metadata: {
    [additionalProperties: string]: string;
  };
};
/**
 * Connection
 *
 * Details about the Connection that was used to authenticate the user.
 */
type Connection = {
  /** The connection's unique identifier. */
  id: string;
  /** The name of the connection used to authenticate the user (such as `twitter` or `some-g-suite-domain`). */
  name: string;
  /** The type of connection. For social connections, `event.connection.strategy === event.connection.name`. For enterprise connections, the strategy is `waad` (Windows Azure AD), `ad` (Active Directory/LDAP), `auth0` (database connections), and so on. */
  strategy: string;
  /** Metadata associated with the connection. */
  metadata?: {
    [additionalProperties: string]: string;
  };
};
/**
 * Factor
 *
 * An object describing an enrolled authentication factor type and any factor-specific options.
 */
type EnrolledFactor = {
  /** The type of authentication factor such as `push-notification`, `phone`, `email`, `otp`, `webauthn-roaming` and `webauthn-platform`. */
  type: string;
  /** Additional options describing this instance of the enrolled factor. */
  options?: {
    [additionalProperties: string]: any;
  };
} & {
  [additionalProperties: string]: any;
};
/** EnrollmentFactorSelector */
type EnrollmentFactorSelector =
  | {
      /** Additional options for configuring a factor of a given type. */
      options?: {
        [property: string]: any;
      };
      /** A type of authentication factor such as `push-notification`, `phone`, `otp`, `webauthn-roaming`, `webauthn-platform`, and `recovery-code`. */
      type:
        | 'otp'
        | 'webauthn-platform'
        | 'webauthn-roaming'
        | 'push'
        | 'push-notification'
        | 'recovery-code';
    }
  | {
      /** Additional options for configuring the phone factor. */
      options?: {
        /** The method passed in this filed will be preferred over the others if available. */
        preferredMethod?: 'sms' | 'voice' | 'both';
      };
      /** A type of authentication factor such as `phone`. */
      type: 'phone';
    };
/** FactorSelector */
type FactorSelector =
  | {
      /** A type of authentication factor such as `push-notification`, `phone`, `email`, `otp`, `webauthn-roaming`, `webauthn-platform`, and `recovery-code`. */
      type: 'otp' | 'email' | 'webauthn-platform' | 'webauthn-roaming' | 'recovery-code';
      /** Additional options for configuring a factor of a given type. */
      options?: {
        [property: string]: any;
      };
    }
  | {
      /** A type of authentication factor such as `phone`. */
      type: 'phone';
      /** Additional options for configuring the phone factor. */
      options?: {
        /** The method passed in this filed will be preferred over the others if available. */
        preferredMethod?: 'sms' | 'voice' | 'both';
      };
    }
  | {
      /** A type of authentication factor such as `push-notification`. */
      type: 'push' | 'push-notification';
      /** Additional options for configuring the push factor. */
      options?: {
        /** If this is set to false, the OTP fallback method for the push factor will not be available for the user. */
        otpFallback?: boolean;
      };
    };
/**
 * LoginStats
 *
 * Login statistics for the current user.
 */
type LoginStats = {
  /** The number of times this user has logged in. */
  logins_count: number;
};
/** Multifactor */
type Multifactor =
  | {
      /** User the provider setting to specify whether to force MFA, and which factor you use */
      provider: 'none' | 'guardian' | 'google-authenticator' | 'any';
      /** When provider is set to `google-authenticator` or `duo`, the user is prompted for MFA once every 30 days. When provider is set to `guardian`, the MFA prompt displays the enrollment checkbox for users to choose whether or not to enroll. Defaults to `false`. To learn more, read [Customize Multi-Factor Authentication Pages](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa). */
      allowRememberBrowser?: boolean;
    }
  | {
      /** User the provider setting to specify whether to force MFA, and which factor you use */
      provider: 'duo';
      /** When provider is set to `google-authenticator` or `duo`, the user is prompted for MFA once every 30 days. When provider is set to `guardian`, the MFA prompt displays the enrollment checkbox for users to choose whether or not to enroll. Defaults to `false`. To learn more, read [Customize Multi-Factor Authentication Pages](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa). */
      allowRememberBrowser?: boolean;
      providerOptions?: {
        /** This is the Client ID (previously Integration key) value from your Duo account. */
        ikey: string;
        /** This is the Client secret (previously Secret key) value from your Duo account. */
        skey: string;
        /** This is the API hostname value from your Duo account. */
        host: string;
        /** Use some attribute of the profile as the username in DuoSecurity. This is also useful if you already have your users enrolled in Duo. */
        username?: string;
      };
    };
/**
 * Organization
 *
 * Details about the Organization associated with the current transaction.
 */
type Organization = {
  /** The Organization identifier. */
  id: string;
  /** The name of the Organization. */
  name: string;
  /** The friendly name of the Organization. */
  display_name: string;
  /** Metadata associated with the Organization. */
  metadata: {
    [additionalProperties: string]: string;
  };
} & {
  [additionalProperties: string]: any;
};
/**
 * Prompt
 *
 * Collected data from rendered custom prompts.
 */
type Prompt = {
  /** The prompt ID. */
  id: string;
  /** Fields and hidden fields data. */
  fields?: {
    [additionalProperties: string]: any;
  };
  /** Shared variables data. */
  vars?: {
    [additionalProperties: string]: any;
  };
};
/** Protocol */
type Protocol = (
  | 'oidc-basic-profile'
  | 'oidc-implicit-profile'
  | 'oauth2-device-code'
  | 'oauth2-resource-owner'
  | 'oauth2-resource-owner-jwt-bearer'
  | 'oauth2-password'
  | 'oauth2-webauthn'
  | 'oauth2-access-token'
  | 'oauth2-refresh-token'
  | 'oauth2-token-exchange'
  | 'oidc-hybrid-profile'
  | 'samlp'
  | 'wsfed'
  | 'wstrust-usernamemixed'
) &
  string;
/**
 * Request
 *
 * Details about the request that initiated the transaction.
 */
type Request = {
  /** The originating IP address of the request. */
  ip: string;
  /** The hostname that is being used for the authentication flow. */
  hostname?: string;
  /** The HTTP method used for the request */
  method: string;
  /** The language requested by the browser. */
  language?: string;
  geoip: {
    countryCode?: string;
    countryCode3?: string;
    countryName?: string;
    cityName?: string;
    latitude?: number;
    longitude?: number;
    timeZone?: string;
    subdivisionCode?: string;
    subdivisionName?: string;
    continentCode?: string;
  } & {
    [additionalProperties: string]: any;
  };
  /** The value of the `User-Agent` header received when initiating the transaction. */
  user_agent?: string;
};
/**
 * RequestWithBody
 *
 * Details about the request that initiated the transaction.
 */
type RequestWithBody = {
  /** The originating IP address of the request. */
  ip: string;
  /** The hostname that is being used for the authentication flow. */
  hostname?: string;
  /** The HTTP method used for the request */
  method: string;
  /** The language requested by the browser. */
  language?: string;
  /** The body of the POST request. This data will only be available during refresh token, Client Credential Exchange flows and PreUserRegistration Action. */
  body: {
    [additionalProperties: string]: any;
  };
  geoip: Geoip;
  /** The value of the `User-Agent` header received when initiating the transaction. */
  user_agent?: string;
};
/**
 * RequestWithParams
 *
 * Details about the request that initiated the transaction.
 */
type RequestWithParams = {
  /** The originating IP address of the request. */
  ip: string;
  /** The hostname that is being used for the authentication flow. */
  hostname?: string;
  /** The HTTP method used for the request */
  method: string;
  /** The language requested by the browser. */
  language?: string;
  /** The query string parameters sent to the authorization request. */
  query: {
    [additionalProperties: string]: any;
  };
  /** The body of the POST request. This data will only be available during refresh token and Client Credential Exchange flows and Post Login Action. */
  body: {
    [additionalProperties: string]: any;
  };
  geoip: Geoip;
  /** The value of the `User-Agent` header received when initiating the transaction. */
  user_agent?: string;
};
/** RequireMultifactorAuth */
type RequireMultifactorAuth =
  | {
      type: 'RequireMultifactorAuth';
      allowRememberBrowser?: boolean;
      provider: 'duo' & string;
      providerOptions?: {
        ikey: string;
        skey: string;
        host: string;
        username?: string;
      };
    }
  | {
      type: 'RequireMultifactorAuth';
      allowRememberBrowser?: boolean;
      provider: ('none' | 'guardian' | 'google-authenticator' | 'any') & string;
    };
/**
 * ResourceServer
 *
 * Details about the resource server to which the access is being requested.
 */
type ResourceServer = {
  /** The identifier of the resource server. For example: `https://your-api.example.com`. */
  identifier: string;
};
/**
 * RiskAssessmentInfo
 *
 * Details about risk assessments obtained during the login or password reset flow.
 */
type RiskAssessmentInfo = {
  /** Overall risk score */
  confidence: ('low' | 'medium' | 'high' | 'neutral') & string;
  version: string;
  assessments: {
    /** Shows if the IP was found in Auth0's repository of low reputation IPs. */
    UntrustedIP?: {
      confidence: ('low' | 'medium' | 'high' | 'neutral') & string;
      code: (
        | 'not_found_on_deny_list'
        | 'found_on_deny_list'
        | 'invalid_ip_address'
        | 'assessment_not_available'
      ) &
        string;
      details?: {
        /** The originating IP address of the request. */
        ip?: string;
        matches?: string;
        source?: string;
        category?: string;
      };
    };
    /** Determines if the user is logging in from a known device. */
    NewDevice?: {
      confidence: ('low' | 'medium' | 'high' | 'neutral') & string;
      code: (
        | 'match'
        | 'partial_match'
        | 'no_match'
        | 'initial_login'
        | 'unknown_device'
        | 'no_device_history'
        | 'assessment_not_available'
      ) &
        string;
      details?: {
        device?: ('known' | 'unknown') & string;
        useragent?: ('known' | 'unknown') & string;
      };
    };
    /** Determines if the user is logging in from a location signaling impossible travel. */
    ImpossibleTravel?: {
      confidence: ('low' | 'medium' | 'high' | 'neutral') & string;
      code: (
        | 'minimal_travel_from_last_login'
        | 'travel_from_last_login'
        | 'substantial_travel_from_last_login'
        | 'impossible_travel_from_last_login'
        | 'invalid_travel'
        | 'missing_geoip'
        | 'anonymous_proxy'
        | 'unknown_location'
        | 'initial_login'
        | 'location_history_not_found'
        | 'assessment_not_available'
      ) &
        string;
    };
  };
};
/**
 * Tenant
 *
 * Details about the Tenant associated with the current transaction.
 */
type Tenant = {
  /** The name of the tenant. */
  id: string;
};
/**
 * Transaction
 *
 * Details about the current transaction.
 */
type Transaction = {
  /** The locale to be used for this transaction as determined by comparing the browser's requested languages to the tenant's language settings. */
  locale: string;
  protocol?: Protocol;
  /** The scopes requested (if any) when starting this authentication flow. */
  requested_scopes: string[];
  /** Any acr_values provided in the original authentication request. */
  acr_values: string[];
  /** The ui_locales provided in the original authentication request. */
  ui_locales: string[];
  /** The URL to which Auth0 will redirect the browser after the transaction is completed. */
  redirect_uri?: string;
  /** List of instructions indicating whether the user may be prompted for re-authentication and consent. */
  prompt?: string[];
  /** Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). */
  login_hint?: string;
  /** Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. */
  response_mode?: ('query' | 'fragment' | 'form_post' | 'web_message') & string;
  /** Denotes the kind of credential that Auth0 will return. */
  response_type?: (('code' | 'token' | 'id_token') & string)[];
  /** An opaque arbitrary alphanumeric string your app adds to the initial request that Auth0 includes when redirecting back to your application. */
  state?: string;
} & {
  [additionalProperties: string]: any;
};
/**
 * User
 *
 * An object describing the user on whose behalf the current transaction was initiated.
 */
type User = {
  /** (unique) User's unique identifier. */
  user_id: string;
  /** (unique) User's username. */
  username?: string;
  /** User's full name. */
  name?: string;
  /** User's given name. */
  given_name?: string;
  /** User's family name. */
  family_name?: string;
  /** User's nickname. */
  nickname?: string;
  /** (unique) User's email address. */
  email?: string;
  /** Indicates whether the user has verified their email address. */
  email_verified: boolean;
  /** User's phone number. */
  phone_number?: string;
  /** Indicates whether the user has verified their phone number. */
  phone_verified?: boolean;
  /** URL pointing to the [user's profile picture](https://auth0.com/docs/users/change-user-picture). */
  picture?: string;
  /** Custom fields that store info about a user that does not impact what they can or cannot access, such as work address, home address, or user preferences. */
  user_metadata: {
    [additionalProperties: string]: any;
  };
  /** Custom fields that store info about a user that influences the user's access, such as support plan, security roles, or access control groups. */
  app_metadata: {
    [additionalProperties: string]: any;
  };
  /** Timestamp indicating when the user profile was first created. */
  created_at: string;
  /** Timestamp indicating when the user's profile was last updated/modified. */
  updated_at: string;
  /** Timestamp indicating the last time the user's password was reset/changed. At user creation, this field does not exist. This property is only available for Database connections. */
  last_password_reset?: string;
} & {
  [additionalProperties: string]: any;
};
/** UserIdentity */
type UserIdentity = {
  /** Name of the Auth0 connection used to authenticate the user. */
  connection?: string;
  /** Name of the entity that is authenticating the user, such as Facebook, Google, SAML, or your own provider. */
  provider?: string;
  /** User's unique identifier for this connection/provider. */
  user_id?: string;
  /** User information associated with the connection. When profiles are linked, it is populated with the associated user info for secondary accounts. */
  profileData?: {
    [additionalProperties: string]: string;
  };
  /** Indicates whether the connection is a social one. */
  isSocial?: boolean;
} & {
  [additionalProperties: string]: any;
};
/** Actor */
type Actor = {
  /** The originating IP address of request. */
  ip: string;
  /** The hostname that is being used for the authentication flow. */
  hostname?: string;
  /** The HTTP method used for the request */
  method?: string;
  /** The language requested by the browser. */
  language?: string;
  /** The body of the POST request. */
  body?: {
    [additionalProperties: string]: any;
  };
  geoIp?: {
    country_code?: string;
    country_code3?: string;
    country_name?: string;
    city_name?: string;
    latitude?: number;
    longitude?: number;
    time_zone?: string;
    subdivision_code?: string;
    subdivision_name?: string;
    continent_code?: string;
  } & {
    [additionalProperties: string]: any;
  };
  userAgent?: string;
};
/** Client */
type Client0 = {
  /** The client id of the application the user is logging in to. */
  id: string;
  /** The name of the application (as defined in the Dashboard). */
  name: string;
  /** An object for holding other application properties. */
  metadata: {
    [additionalProperties: string]: string;
  };
};
/** CredentialsExchangeCommand */
type CredentialsExchangeCommand = {
  type: 'deny';
  reason: ('invalid_scope' | 'invalid_request' | 'server_error') & string;
  message: string;
};
/**
 * CredentialsExchangeTransaction
 *
 * Details about the client credentials exchange transaction.
 */
type CredentialsExchangeTransaction = {
  /** The scopes specified (if any) when requesting the access token. */
  requested_scopes: string[];
};
/** Tenant */
type Tenant0 = {
  /** The name of the tenant. */
  id: string;
};
/** CredentialsExchangeV1Event */
type CredentialsExchangeV1Event = {
  actor: Actor;
  client: Client0;
  tenant: Tenant0;
  audience: string;
  scope: string[];
  customClaims: {
    [additionalProperties: string]: any;
  };
  command?: CredentialsExchangeCommand;
};
/** CredentialsExchangeV1Result */
type CredentialsExchangeV1Result = {
  scope?: Scope;
  customClaims?: CustomClaims;
  command?: CredentialsExchangeCommand;
};
/** CredentialsExchangeV2Event */
type CredentialsExchangeV2Event = {
  /** Details about the request that initiated the transaction. */
  request: RequestWithBody;
  /** Information about the Client used during this token exchange. */
  client: Client;
  /** Information about the Tenant used during this token exchange. */
  tenant: Tenant;
  /** Information about the Resource Server that is issueing the access tokeResource Server that is issuing the access token. */
  resource_server: ResourceServer;
  /** Information about the Credentials Exchange transaction. */
  transaction: CredentialsExchangeTransaction;
  /** Information about the access token to be issued. */
  accessToken: AccessToken;
  /** Details about the Organization associated with the current transaction. */
  organization?: Organization;
};
/** CustomEmailProviderEvent */
type CustomEmailProviderEvent = {
  client: Client;
  connection?: Connection;
  organization?: Organization;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: {
    user_id: UserId;
    username?: Username;
    name?: Name;
    given_name?: GivenName;
    family_name?: FamilyName;
    nickname?: Nickname;
    email?: Email;
    email_verified: EmailVerified;
    picture?: Picture;
    user_metadata: UserMetadata;
    app_metadata: AppMetadata;
  } & {
    [additionalProperties: string]: any;
  };
  notification: {
    /** The type of message that is being send, like `verify_email` or `welcome_email`. */
    message_type:
      | 'verify_email'
      | 'verify_email_by_code'
      | 'reset_email'
      | 'reset_email_by_code'
      | 'welcome_email'
      | 'verification_code'
      | 'mfa_oob_code'
      | 'enrollment_email'
      | 'blocked_account'
      | 'stolen_credentials'
      | 'try_provider_configuration_email'
      | 'organization_invitation';
    /** Email address of the recipient. */
    to: string;
    /** The locale we rendered the message in, example `en_US`, as defined in the BCP-47 specification. */
    locale: string;
    /** Rendered HTML template. */
    html: string;
    /** Rendered text template. */
    text: string;
    /** Email address of the sender for the email. */
    from: string;
    /** Subject to be attached to the email. */
    subject: string;
  };
  request: {
    user_agent?: UserAgent;
    ip?: Ip;
    geoip?: Geoip;
    /** The query string parameters sent to the authorization request. */
    query?: {
      [additionalProperties: string]: string;
    };
  };
  tenant: {
    /** The name of the tenant. */
    id: string;
    /** The friendly name for the tenant, usually a more human-readable version of the ID. */
    friendly_name?: string;
    /** The home URL for the tenant, if defined and as found in its settings. */
    home_url?: string;
    /** The logo URL for the tenant, if defined and as found in its settings. */
    logo_url?: string;
    /** The email to the tenant's support service, if defined and as found in its settings. */
    support_email?: string;
    /** The url to the tenant's support service, if defined and as found in its settings. */
    support_url?: string;
  };
};
/** CustomEmailProviderV1Event */
type CustomEmailProviderV1Event = CustomEmailProviderEvent;
/** CustomPhoneProviderEvent */
type CustomPhoneProviderEvent = {
  client: Client;
  connection?: Connection;
  organization?: Organization;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User &
    ({
      /** Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
      identities?: UserIdentity[];
    } & {
      [additionalProperties: string]: any;
    });
  request: Request;
  notification: {
    /** The type of message that is being send, like `otp_verify` or `blocked_account`. */
    message_type:
      | 'otp_verify'
      | 'otp_enroll'
      | 'blocked_account'
      | 'change_password'
      | 'password_breach';
    /** The E.164 compliant phone number for the recipient. */
    recipient: string;
    /** The E.164 compliant phone number for the sender. */
    from?: string;
    /** The text, as we rendered it, ready to be delivered as a text message. */
    as_text: string;
    /** The text, as we rendered it, ready to be delivered as a voicetext message. */
    as_voice: string;
    /** The way the message should be delivered. Could be `text` or `voice`. */
    delivery_method: 'text' | 'voice';
    /** The locale we rendered the message in, example `en_US`, as defined in the BCP-47 specification. */
    locale?: string;
    /** The One Time Password that we drawn for this message for some types (e.g. `otp_verify`, `otp_enroll`). If provided, it is important to have it conveyed to the end-user. */
    code?: string;
  };
  tenant: {
    /** The name of the tenant. */
    id: string;
    /** The friendly name for the tenant, usually a more human-readable version of the ID. */
    friendly_name?: string;
    /** The home URL for the tenant, if defined and as found in its settings. */
    home_url?: string;
    /** The logo URL for the tenant, if defined and as found in its settings. */
    logo_url?: string;
    /** The email to the tenant's support service, if defined and as found in its settings. */
    support_email?: string;
    /** The url to the tenant's support service, if defined and as found in its settings. */
    support_url?: string;
  };
};
/** CustomPhoneProviderV1Event */
type CustomPhoneProviderV1Event = CustomPhoneProviderEvent;
/**
 * CustomTokenExchangeTransaction
 *
 * Details about the current custom token exchange transaction.
 */
type CustomTokenExchangeTransaction = {
  /** The subject_token_type provided in the token exchange request. */
  subject_token_type: string;
  /** The subject token provided in the token exchange request. */
  subject_token: string;
  /** The scopes requested (if any) provided in the token exchange request. */
  requested_scopes: string[];
  /** The type of token to be generated by Auth0. For example: urn:ietf:params:oauth:token-type:access_token. */
  requested_token_type: string | null;
};
/** CustomTokenExchangeEvent */
type CustomTokenExchangeEvent = {
  /** Information about the Client with which this transaction was initiated. */
  client: Client;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the request that initiated the transaction. */
  request: RequestWithBody;
  /** Details about the current custom token exchange transaction. */
  transaction: CustomTokenExchangeTransaction;
  /** Details about the resource server to which the access is being requested. */
  resource_server: ResourceServer;
};
/** CustomTokenExchangeV1Event */
type CustomTokenExchangeV1Event = CustomTokenExchangeEvent;
/**
 * CustomTokenExchangeBetaTransaction
 *
 * Details about the current custom token exchange transaction.
 */
type CustomTokenExchangeBetaTransaction = {
  /** The subject_token_type provided in the token exchange request. */
  subject_token_type: string;
  /** The subject token provided in the token exchange request. */
  subject_token: string;
  /** The scopes requested (if any) provided in the token exchange request. */
  requested_scopes: string[];
  /** The type of token to be generated by Auth0. For example: urn:ietf:params:oauth:token-type:access_token. */
  requested_token_type: string | null;
};
/** CustomTokenExchangeBetaEvent */
type CustomTokenExchangeBetaEvent = {
  /** Information about the Client with which this transaction was initiated. */
  client: Client;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the request that initiated the transaction. */
  request: RequestWithBody;
  /** Details about the current custom token exchange transaction. */
  transaction: CustomTokenExchangeBetaTransaction;
  /** Details about the resource server to which the access is being requested. */
  resource_server: ResourceServer;
};
/** CustomTokenExchangeBetaV1Event */
type CustomTokenExchangeBetaV1Event = CustomTokenExchangeBetaEvent;
/** LoginPostIdentifierEvent */
type LoginPostIdentifierEvent = {
  /** Details about the request that initiated the transaction. */
  request: RequestWithParams;
  /** Information about the Client with which this login transaction was initiated. */
  client: Client;
  /** Details about the Connection that was specified to authenticate the user. */
  connection?: Connection;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the Organization associated with the current transaction. */
  organization?: Organization;
  /** Details about the current transaction. */
  transaction: Transaction &
    ({
      /** The login identifier specified by the user. */
      identifier: string;
    } & {
      [additionalProperties: string]: any;
    });
  /** Details about the resource server to which the access is being requested. */
  resource_server?: ResourceServer;
};
/**
 * Authentication
 *
 * Details about authentication obtained during the password reset flow.
 */
type Authentication = {
  /** Contains the authentication methods a user has completed during their session. */
  methods: AuthenticationMethod[];
};
/**
 * Transaction
 *
 * Details about the current credential reset transaction.
 */
type Transaction0 = {
  /** The locale to be used for this transaction as determined by comparing the browser's requested languages to the tenant's language settings. */
  locale: string;
  /** The ui_locales provided in the original authentication request. */
  ui_locales: string[];
  /** Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). */
  login_hint?: string;
  /** An opaque arbitrary alphanumeric string your app adds to the initial request that Auth0 includes when redirecting back to your application. */
  state?: string;
} & {
  [additionalProperties: string]: any;
};
/**
 * PasswordResetPostChallengeEvent
 *
 * Event Object for the Password Reset Post Challenge
 */
type PasswordResetPostChallengeEvent = {
  /** Details about the request that initiated the transaction. */
  request: RequestWithParams;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the Organization associated with the current transaction. */
  organization?: Organization;
  /** Information about the Client with which this password reset transaction was initiated. */
  client: Client;
  /** Details about the Connection that was used to authenticate the user. */
  connection: Connection;
  /** Details about authentication obtained during the password reset flow. */
  authentication: Authentication;
  /** An object containing information describing the authorization granted to the user who is logging in. */
  authorization: AuthorizationInfo;
  /** Login statistics for the current user. */
  stats: LoginStats;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User &
    ({
      /** An array of authentication factors that the user has enrolled. Empty array means the user has no enrolled factors.  If enrolledFactors is undefined, the system was unable fetch the information, the user may or may not have enrolled factors. */
      enrolledFactors?: EnrolledFactor[];
    } & {
      [additionalProperties: string]: any;
    }) &
    ({
      /** Contains info retrieved from the identity provider with which the user originally authenticated. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
      identities: UserIdentity[];
    } & {
      [additionalProperties: string]: any;
    });
  /** Collected data from rendered custom prompts. */
  prompt?: Prompt;
  /** Details about the current transaction. */
  transaction: Transaction0;
};
/** PasswordResetPostChallengeV1Event */
type PasswordResetPostChallengeV1Event = PasswordResetPostChallengeEvent;
/** PostChangePasswordV1Event */
type PostChangePasswordV1Event = {
  connection: {
    id: Id;
    name: Name0;
  };
  tenant: Tenant;
  user: {
    id: UserId;
    username?: Username;
    email?: Email;
    last_password_reset?: LastPasswordReset;
  };
};
/** PostChangePasswordResult */
type PostChangePasswordV1Result = {
  [property: string]: any;
};
/** PostChangePasswordV2Event */
type PostChangePasswordV2Event = {
  /** Details about the request that initiated the transaction. */
  request: Request;
  /** Details about the Connection that was used for the current transaction. */
  connection: Connection;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: {
    /** (unique) User's unique identifier. */
    user_id?: string;
    /** (unique) User's username. */
    username?: string;
    /** (unique) User's email address. */
    email?: string;
    /** Indicates whether the user has verified their email address. */
    email_verified?: boolean;
    /** (unique) User's phone number. */
    phone_number?: string;
    /** Indicates whether the user has verified their phone number. */
    phone_verified?: boolean;
    /** Timestamp indicating the last time the user's password was reset/changed. At user creation, this field does not exist. This property is only available for Database connections. */
    last_password_reset?: string;
  };
};
/** Actor */
type Actor0 = {
  /** The originating IP address of request. */
  ip: string;
  /** The ASN (autonomous system number) of the user-agent making the request. */
  asn?: string;
  /** The hostname that is being used for the authentication flow. */
  hostname?: string;
  /** The HTTP method used for the request */
  method: string;
  /** The language requested by the browser. */
  language?: string;
  /** The query string parameters sent to the authorization request. */
  query: {
    [additionalProperties: string]: any;
  };
  /** The body of the POST request made to the authorization endpoint. */
  body?: {
    [additionalProperties: string]: any;
  };
  geoIp?: {
    country_code?: string;
    country_code3?: string;
    country_name?: string;
    city_name?: string;
    latitude?: number;
    longitude?: number;
    subdivision_code?: string;
    subdivision_name?: string;
    time_zone?: string;
    continent_code?: string;
  } & {
    [additionalProperties: string]: any;
  };
  userAgent?: string;
};
/**
 * AuthenticationInfo
 *
 * Details about authentication signals obtained during the login flow.
 */
type AuthenticationInfo = {
  /** Contains the authentication methods a user has completed during their session. */
  methods: AuthenticationMethod[];
};
/**
 * Client
 *
 * Information about the Client with which this login transaction was initiated.
 */
type Client1 = {
  /** The client id of the application to which the user is logging in. */
  id: string;
  /** The name of the application (as defined in the Dashboard). */
  name: string;
  /** An object for holding other application properties. */
  metadata: {
    [additionalProperties: string]: string;
  };
};
/** IDToken */
type IDToken = {
  customClaims: {
    [additionalProperties: string]: any;
  };
  scope: string[];
};
/** Protocol */
type LegacyProtocol = (
  | 'oidc-basic-profile'
  | 'oidc-implicit-profile'
  | 'oauth2-device-code'
  | 'oauth2-resource-owner'
  | 'oauth2-resource-owner-jwt-bearer'
  | 'oauth2-password'
  | 'oauth2-webauthn'
  | 'oauth2-access-token'
  | 'oauth2-refresh-token'
  | 'oauth2-token-exchange'
  | 'oidc-hybrid-profile'
  | 'samlp'
  | 'wsfed'
  | 'wstrust-usernamemixed'
  | 'delegation'
  | 'redirect-callback'
) &
  string;
/** LoginStats */
type LoginStats0 = {
  /** The number of times this user has logged in. */
  loginsCount: number;
};
/** PostLoginCommand */
type PostLoginCommand =
  | {
      /** Deny the authentication request. */
      type: 'deny';
      /** The reason why an authentication request is being denied. */
      reason: string;
      /** The message that will appear to the user who is being denied. */
      message: string;
    }
  | {
      /** Perform a redirect. */
      type: 'redirect';
      /** A url specifying where Auth0 will redirect the user. */
      url: string;
    }
  | {
      /** Trigger MFA */
      type: 'multifactor';
      provider: string;
      allowRememberBrowser?: boolean;
    };
/** RefreshToken */
type RefreshToken = {
  /** [Enterprise Customers] The ID of the refresh token. */
  id: string;
  /** [Enterprise Customers] The ID of the session bound to the refresh token. */
  session_id?: string;
  /** [Enterprise Customers] The ID of the user bound to the refresh token. */
  user_id?: string;
  /** [Enterprise Customers] Timestamp of when the refresh token was created. */
  created_at: string;
  /** [Enterprise Customers] Timestamp of when the refresh token will idle expire. */
  idle_expires_at?: string;
  /** [Enterprise Customers] Timestamp of when the refresh token will absolutely expire. */
  expires_at?: string;
  /** [Enterprise Customers] Timestamp of when the refresh token was last successfully exchanged. */
  last_exchanged_at?: string;
  /** [Enterprise Customers] The ID of the client associated with the refresh token. */
  client_id?: string;
  /** [Enterprise Customers] If the refresh token is a rotating refresh token. */
  rotating?: boolean;
  resource_servers?: {
    /** [Enterprise Customers] The audience of the refresh token. */
    audience: string;
    /** [Enterprise Customers] Scopes of the refresh token. */
    scopes: string;
  }[];
  device?: {
    /** [Enterprise Customers] First autonomous system number associated with this refresh token. */
    initial_asn?: string;
    /** [Enterprise Customers] First IP address associated with this refresh token. */
    initial_ip?: string;
    /** [Enterprise Customers] First user agent of the device associated with this refresh token. */
    initial_user_agent?: string;
    /** [Enterprise Customers] Last IP address from which this refresh token was last exchanged. */
    last_ip?: string;
    /** [Enterprise Customers] Last autonomous system number from which this refresh token was last exchanged. */
    last_asn?: string;
    /** [Enterprise Customers] Last user agent of the device from which this refresh token was last exchanged. */
    last_user_agent?: string;
  };
};
/**
 * RichAuthorizationDetails
 *
 * The details of a rich authorization request per Section 2 of the Rich Authorization Requests spec at https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar#section-2.
 */
type RichAuthorizationDetails = ({
  /** The type of authorization details as a string. The value of the type field determines the allowable contents of the object which contains it. */
  type: string;
} & {
  [additionalProperties: string]: any;
})[];
/** Session */
type Session0 = {
  /** The ID of the current session. */
  id: string;
  /** [Enterprise Customers] Metadata related to the device used in the session. */
  device?: {
    /** [Enterprise Customers] First autonomous system number associated with this session. */
    initial_asn?: string;
    /** [Enterprise Customers] First IP address associated with this session. */
    initial_ip?: string;
    /** [Enterprise Customers] First user agent of the device associated with this session. */
    initial_user_agent?: string;
    /** [Enterprise Customers] Last IP address from which this user logged in. */
    last_ip?: string;
    /** [Enterprise Customers] Last autonomous system number from which this user logged in. */
    last_asn?: string;
    /** [Enterprise Customers] Last user agent of the device from which this user logged in. */
    last_user_agent?: string;
  };
  /** [Enterprise Customers] ID of the user which can be used when interacting with other APIs. */
  user_id?: string;
  /** [Enterprise Customers] The date and time when the session was created. */
  created_at?: string;
  /** [Enterprise Customers] The date and time when the session was last updated. */
  updated_at?: string;
  /** [Enterprise Customers] The date and time when the session was last authenticated. */
  authenticated_at?: string;
  /** [Enterprise Customers] The date and time when the session will expire if idle. */
  idle_expires_at?: string;
  /** [Enterprise Customers] The date and time when the session will expire. */
  expires_at?: string;
  /** [Enterprise Customers] The date and time when the session was last successfully interacted with. */
  last_interacted_at?: string;
  /** [Enterprise Customers] List of client details for the session. */
  clients?: {
    /** [Enterprise Customers] ID of client for the session. */
    client_id: string;
  }[];
};
/** Details about the current transaction. */
type Transaction1 = Transaction &
  ({
    /** The details of a rich authorization request per Section 2 of the Rich Authorization Requests spec at https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar#section-2. */
    requested_authorization_details?: RichAuthorizationDetails;
    /** Dynamic Linking ID that allows developers to reference this transaction. */
    linking_id?: string;
  } & {
    [additionalProperties: string]: any;
  });
/** UserV1 */
type User0 = {
  /** (unique) User's unique identifier. */
  id: string;
  /** (unique) User's username. */
  username?: string;
  /** User's full name. */
  name?: string;
  /** User's given name. */
  givenName?: string;
  /** User's famiky name. */
  familyName?: string;
  /** User's nickname. */
  nickname?: string;
  /** (unique) User's email address. */
  email?: string;
  /** Indicates whether the user has verified their email address. */
  emailVerified: boolean;
  /** User's phone number. */
  phoneNumber?: string;
  /** Indicates whether the user has verified their phone number. */
  phoneNumberVerified?: boolean;
  /** URL pointing to the [user's profile picture](https://auth0.com/docs/users/change-user-picture). */
  picture?: string;
  /** Custom fields that store info about a user that does not impact what they can or cannot access, such as work address, home address, or user preferences. */
  userMetadata: {
    [additionalProperties: string]: any;
  };
  /** Custom fields that store info about a user that influences the user's access, such as support plan, security roles, or access control groups. */
  appMetadata: {
    [additionalProperties: string]: any;
  };
  /** Timestamp indicating when the user profile was first created. */
  createdAt: string;
  /** Timestamp indicating when the user's profile was last updated/modified. */
  updatedAt: string;
  /** Timestamp indicating the last time the user's password was reset/changed. At user creation, this field does not exist. This property is only available for Database connections. */
  lastPasswordResetAt?: string;
  /** Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
  identities: UserIdentity0[];
  /** List of multi-factor authentication (MFA) providers with which the user is enrolled. This array is updated when the user enrolls in MFA and when an administrator resets a user's MFA enrollments. */
  multifactor?: string[];
  /** An an array of the authentication factors defined by within the current tenant. */
  enrolledFactors?: EnrolledFactor[];
} & {
  [additionalProperties: string]: any;
};
/** UserIdentity */
type UserIdentity0 = {
  /** Name of the Auth0 connection used to authenticate the user. */
  connection?: string;
  /** Name of the entity that is authenticating the user, such as Facebook, Google, SAML, or your own provider. */
  provider?: string;
  /** User's unique identifier for this connection/provider. */
  userId?: string;
  /** User information associated with the connection. When profiles are linked, it is populated with the associated user info for secondary accounts. */
  profileData?: {
    [additionalProperties: string]: string;
  };
  /** Indicates whether the connection is a social one. */
  isSocial?: boolean;
  /** The API Access Token to be used with the provider */
  accessToken?: string;
} & {
  [additionalProperties: string]: any;
};
/** PostLoginV1Event */
type PostLoginV1Event = {
  actor: Actor0;
  authentication?: AuthenticationInfo;
  authorization?: AuthorizationInfo;
  client: Client1;
  connection: Connection;
  accessToken: AccessToken;
  idToken: IDToken;
  protocol: LegacyProtocol;
  stats: LoginStats0;
  tenant: Tenant;
  user: User0;
  command?: PostLoginCommand;
  organization?: Organization;
};
/** PostLoginV1Result */
type PostLoginV1Result = {
  accessToken?: TokenRequestV1;
  idToken?: TokenRequestV1;
  user?: {
    appMetadata?: AppMetadata0;
    userMetadata?: UserMetadata0;
  };
  command?: PostLoginCommand;
};
/** TokenRequestV1 */
type TokenRequestV1 = {
  /** A map of custom claims to be added to the token. The claim keys should take the form of an HTTPS URI. */
  customClaims?: {
    [additionalProperties: string]: any;
  };
  /** A list of scopes to be included in the token. */
  scope?: string[];
};
/**
 * LoginStatsV2
 *
 * Login statistics for the current user.
 */
type LoginStatsV2 = {
  /** The number of times this user has logged in. */
  logins_count: number;
};
/** PostLoginV2Event */
type PostLoginV2Event = {
  /** Details about the request that initiated the transaction. */
  request: RequestWithParams;
  /** Details about authentication signals obtained during the login flow. */
  authentication?: AuthenticationInfo;
  /** An object containing information describing the authorization granted to the user who is logging in. */
  authorization?: AuthorizationInfo;
  /** Information about the Client with which this login transaction was initiated. */
  client: Client;
  /** Details about the Connection that was used to authenticate the user. */
  connection: Connection;
  /** Login statistics for the current user. */
  stats: LoginStatsV2;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User &
    ({
      /** List of multi-factor authentication (MFA) providers with which the user is enrolled. This array is updated when the user enrolls in MFA and when an administrator resets a user's MFA enrollments. */
      multifactor?: string[];
      /** Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
      identities: UserIdentity[];
    } & {
      [additionalProperties: string]: any;
    });
  /** Details about the Organization associated with the current transaction. */
  organization?: Organization;
  /** Details about the current transaction. */
  transaction?: Transaction1;
  /** Details about the resource server to which the access is being requested. */
  resource_server?: ResourceServer;
};
/** PostLoginV3Event */
type PostLoginV3Event = {
  /** Details about the request that initiated the transaction. */
  request: {
    /** The originating IP address of the request. */
    ip: string;
    /** The hostname that is being used for the authentication flow. */
    hostname?: string;
    /** The HTTP method used for the request */
    method: string;
    /** The language requested by the browser. */
    language?: string;
    /** The query string parameters sent to the authorization request. */
    query: {
      [additionalProperties: string]: any;
    };
    /** The body of the POST request. This data will only be available during refresh token and Client Credential Exchange flows and Post Login Action. */
    body: {
      [additionalProperties: string]: any;
    };
    geoip: Geoip;
    /** The value of the `User-Agent` header received when initiating the transaction. */
    user_agent?: string;
    /** The ASN (autonomous system number) of the user-agent making the request. */
    asn?: string;
  };
  /** Details about authentication signals obtained during the login flow. */
  authentication?: AuthenticationInfoWithRiskAssessment;
  /** An object containing information describing the authorization granted to the user who is logging in. */
  authorization?: AuthorizationInfo;
  /** Information about the Client with which this login transaction was initiated. */
  client: Client;
  /** Details about the Connection that was used to authenticate the user. */
  connection: Connection;
  /** [Enterprise Customers] The current refresh token. */
  refresh_token?: RefreshToken;
  /** The current login session. */
  session?: Session0;
  /** Login statistics for the current user. */
  stats: LoginStatsV2;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User &
    ({
      /** An an array of authentication factors that the user has enrolled. */
      enrolledFactors?: EnrolledFactor[];
      /** List of multi-factor authentication (MFA) providers with which the user is enrolled. This array is updated when the user enrolls in MFA and when an administrator resets a user's MFA enrollments. */
      multifactor?: string[];
    } & {
      [additionalProperties: string]: any;
    }) &
    ({
      /** Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
      identities: UserIdentity[];
    } & {
      [additionalProperties: string]: any;
    });
  /** Details about the Organization associated with the current transaction. */
  organization?: Organization;
  /** Collected data from rendered custom prompts. */
  prompt?: Prompt;
  /** Details about the current transaction. */
  transaction?: Transaction1;
  /** Details about the resource server to which the access is being requested. */
  resource_server?: ResourceServer;
};
/** PostUserRegistrationV1Event */
type PostUserRegistrationV1Event = {
  connection: {
    id: Id;
    name: Name0;
  };
  tenant: Tenant;
  request?: {
    ip?: Ip;
    language?: string;
  };
  requestLanguage?: string;
  renderLanguage?: string;
  user: {
    id: UserId;
    tenant?: Id0;
    username?: Username;
    email?: Email;
    emailVerified?: EmailVerified;
    phoneNumber?: PhoneNumber;
    phoneNumberVerified?: PhoneVerified;
    app_metadata?: AppMetadata;
    user_metadata?: UserMetadata;
  };
};
/** PostUserRegistrationV1Result */
type PostUserRegistrationV1Result = {
  [property: string]: any;
};
/** PostUserRegistrationV2Event */
type PostUserRegistrationV2Event = {
  /** Details about the request that initiated the transaction. */
  request?: Request;
  /** Details about the Connection that was used to register the user. */
  connection: Connection;
  tenant: Tenant;
  /** Details about the current transaction. */
  transaction?: Transaction;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User;
};
/** PreUserRegistrationCommand */
type PreUserRegistrationCommand = {
  /** Prevent a user from registering */
  type: 'deny';
  /** The reason field controls the error message that appears in your tenant logs. */
  reason: string;
  /** The message field controls the error message seen by the user who is attempting to register. */
  message: string;
};
/** PreUserRegistrationV1Event */
type PreUserRegistrationV1Event = {
  command?: PreUserRegistrationCommand;
  connection: {
    id?: Id;
    name?: Name0;
  };
  tenant: Tenant;
  request: {
    ip: Ip;
    language?: string;
  } & {
    [additionalProperties: string]: any;
  };
  requestLanguage?: string;
  renderLanguage?: string;
  user: {
    tenant?: Id0;
    username?: Username;
    /** Unecrypted password */
    password?: string;
    email?: Email;
    emailVerified?: EmailVerified;
    phoneNumber?: PhoneNumber;
    phoneNumberVerified?: PhoneVerified;
    app_metadata?: AppMetadata;
    user_metadata?: UserMetadata;
  };
};
/** PreUserRegistrationV1Result */
type PreUserRegistrationV1Result = {
  command?: PreUserRegistrationCommand;
  user?: {
    app_metadata?: AppMetadata;
    user_metadata?: UserMetadata;
  } & {
    [additionalProperties: string]: any;
  };
};
/** PreUserRegistrationV2Event */
type PreUserRegistrationV2Event = {
  /** Details about the request that initiated the transaction. */
  request: RequestWithBody;
  /** Details about the Connection that was used to register the user. */
  connection: Connection;
  /** Information about the Client with which this transaction was initiated. */
  client?: Client;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the current transaction. */
  transaction?: Transaction;
  /** An object describing the user who is attempting to register. */
  user: {
    username?: Username;
    email?: Email;
    app_metadata?: AppMetadata;
    user_metadata?: UserMetadata;
    name?: Name;
    given_name?: GivenName;
    family_name?: FamilyName;
    nickname?: Nickname;
    phone_number?: PhoneNumber;
    picture?: Picture;
  };
};
/** MessageOptions */
type MessageOptions = {
  /** Phone number where the message will be sent. */
  recipient: string;
  /** Content of the message to be sent. */
  text: string;
  /** How the message will be delivered, either by 'sms' or 'voice'. */
  message_type: ('sms' | 'voice') & string;
  /** The flow that triggered this action. */
  action: ('enrollment' | 'second-factor-authentication') & string;
  /** One-time password that the user needs to use to enter in the form. */
  code: string;
};
/** SendPhoneMessageV1Event */
type SendPhoneMessageV1Event = {
  recipient: Recipient;
  text: Text;
  message_type: MessageType;
  action: Action;
  code: Code;
  language: string;
  user_agent: string;
  ip?: Ip;
  client?: {
    client_id?: ClientId;
    name?: Name1;
    client_metadata?: Metadata0;
  };
  user: {
    user_id?: UserId;
    name?: Name;
    email?: Email;
    app_metadata?: AppMetadata;
    user_metadata?: UserMetadata;
  };
};
/** SendPhoneMessageV1Result */
type SendPhoneMessageV1Result = {
  [property: string]: any;
};
/** SendPhoneMessageV2Event */
type SendPhoneMessageV2Event = {
  /** Details about the message that is sent to the user. */
  message_options: MessageOptions;
  /** Information about the Client with which this transaction was initiated. */
  client?: Client;
  /** Details about the Tenant associated with the current transaction. */
  tenant: Tenant;
  /** Details about the request that initiated the transaction. */
  request: Request;
  /** An object describing the user on whose behalf the current transaction was initiated. */
  user: User &
    ({
      /** Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider. */
      identities?: UserIdentity[];
    } & {
      [additionalProperties: string]: any;
    });
};
/** The custom prompt ID. */
type PromptId = string;
type PromptOptions = {
  /** Key-value pairs to populate field values (client-side). */
  fields?: {
    [patternProperties: string]: any;
  };
  /** Key-value pairs to inject variables (server-side). */
  vars?: {
    [patternProperties: string]: any;
  };
};
type Geoip = {
  countryCode?: string;
  countryCode3?: string;
  countryName?: string;
  cityName?: string;
  latitude?: number;
  longitude?: number;
  timeZone?: string;
  subdivisionCode?: string;
  subdivisionName?: string;
  continentCode?: string;
} & {
  [additionalProperties: string]: any;
};
type SAMLAttributeValue = string | number | boolean | null | (string | number | boolean)[];
type Scope = string[];
type CustomClaims = {
  [additionalProperties: string]: any;
};
/** (unique) User's unique identifier. */
type UserId = string;
/** (unique) User's username. */
type Username = string;
/** User's full name. */
type Name = string;
/** User's given name. */
type GivenName = string;
/** User's family name. */
type FamilyName = string;
/** User's nickname. */
type Nickname = string;
/** (unique) User's email address. */
type Email = string;
/** Indicates whether the user has verified their email address. */
type EmailVerified = boolean;
/** URL pointing to the [user's profile picture](https://auth0.com/docs/users/change-user-picture). */
type Picture = string;
/** Custom fields that store info about a user that does not impact what they can or cannot access, such as work address, home address, or user preferences. */
type UserMetadata = {
  [additionalProperties: string]: any;
};
/** Custom fields that store info about a user that influences the user's access, such as support plan, security roles, or access control groups. */
type AppMetadata = {
  [additionalProperties: string]: any;
};
/** The value of the `User-Agent` header received when initiating the transaction. */
type UserAgent = string;
/** The originating IP address of the request. */
type Ip = string;
/** An object containing the user profile attributes to set. */
type SetUserByConnectionUserAttributes = {
  /** The user's email. */
  email?: string;
  /** Whether this email address is verified (true) or unverified (false). User will receive a verification email after creation if email_verified is false or not specified. */
  email_verified?: boolean;
  /** The user's phone number (following the E.164 recommendation). */
  phone_number?: string;
  /** Whether this phone number has been verified (true) or not (false). */
  phone_verified?: boolean;
  /** The user's given name(s). */
  given_name?: string;
  /** The user's family name(s). */
  family_name?: string;
  /** The user's full name. */
  name?: string;
  /** The user's username. */
  username?: string;
  /** The user's nickname. */
  nickname?: string;
  /** A URI pointing to the user's picture. */
  picture?: string;
  /** The user's unique identifier within the connection. */
  user_id: string;
  /** Whether the user will receive a verification email after creation (true) or no email (false). Overrides behavior of email_verified parameter. */
  verify_email?: boolean;
} & {
  [additionalProperties: string]: any;
};
/** An object containing the user profile attributes to set. */
type SetUserByConnectionOptions = {
  /** Behaviour to apply if no user with the specified user_id exists in the connection. Can be 'create_if_not_exists', which will cause a new user to be created using the supplied user attributes; or 'none', which will result in no user being created and an error being returned if no user exists. */
  creationBehavior: ('create_if_not_exists' | 'none') & string;
  /** Behaviour to apply if a user with specified user_id already exists in the connection. Can be 'replace', which results in the existing user's attributes being replaced with the specified user attributes; or 'none' which means the existing user will not be modified. */
  updateBehavior: ('replace' | 'none') & string;
};
/** The connection's unique identifier. */
type Id = string;
/** The name of the connection used to authenticate the user (such as `twitter` or `some-g-suite-domain`). */
type Name0 = string;
/** Timestamp indicating the last time the user's password was reset/changed. At user creation, this field does not exist. This property is only available for Database connections. */
type LastPasswordReset = string;
/** Custom fields that store info about a user that influences the user's access, such as support plan, security roles, or access control groups. */
type AppMetadata0 = {
  [additionalProperties: string]: any;
};
/** Custom fields that store info about a user that does not impact what they can or cannot access, such as work address, home address, or user preferences. */
type UserMetadata0 = {
  [additionalProperties: string]: any;
};
/** The name of the tenant. */
type Id0 = string;
/** User's phone number. */
type PhoneNumber = string;
/** Indicates whether the user has verified their phone number. */
type PhoneVerified = boolean;
/** Phone number where the message will be sent. */
type Recipient = string;
/** Content of the message to be sent. */
type Text = string;
/** How the message will be delivered, either by 'sms' or 'voice'. */
type MessageType = ('sms' | 'voice') & string;
/** The flow that triggered this action. */
type Action = ('enrollment' | 'second-factor-authentication') & string;
/** One-time password that the user needs to use to enter in the form. */
type Code = string;
/** The client id of the application the user is logging in to. */
type ClientId = string;
/** The name of the application (as defined in the Dashboard). */
type Name1 = string;
/** An object for holding other application properties. */
type Metadata0 = {
  [additionalProperties: string]: string;
};

declare interface ValidationAPI {
  /**
   * Throw an error when there is a validation error.
   *
   * @param errorCode A customer defined error code for the validation error.
   *
   * @param errorMessage A customer defined message for the validation error.
   */
  error(errorCode: string, errorMessage: string): PostLoginAPI;
}

declare interface Secrets {

}
declare interface Configuration {}
declare interface BaseEvent extends PostLoginV3Event {
  /**
   * @private Configuration values associated with this Action.
   */
  readonly configuration: Configuration;
  /**
   * Secret values securely associated with this Action.
   */
  readonly secrets: Secrets;
}
declare type TEvent<
  IDs extends AddonID[] = AddonID[],
  Registry extends GeneratedRegistry | undefined = undefined,
> = WithAddons<BaseEvent, IDs, Registry>;

declare interface AccessAPI {
  /**
   * Mark the current login attempt as denied. This will prevent the end-user from completing
   * the login flow. This will *NOT* cancel other user-related side-effects (such as metadata
   * changes) requested by this Action. The login flow will immediately stop following the
   * completion of this action and no further Actions will be executed.
   *
   * @param reason A human-readable explanation for rejecting the login. This may be presented
   * directly in end-user interfaces.
   */
  deny(reason: string): PostLoginAPI;
}

declare interface AccessTokenAPI {
  /**
   * Set a custom claim on the Access Token that will be issued upon completion of the login flow.
   *
   * @param key Name of the claim (note that this may need to be a fully-qualified url).
   * @param value The value of the claim.
   */
  setCustomClaim(key: string, value: unknown): PostLoginAPI;
  /**
   * Add a scope on the Access Token that will be issued upon completion of the login flow.
   *
   * @param scope The scope to be added.
   * @throws will throw an error if scope is invalid
   */
  addScope(scope: string): void;
  /**
   * Remove a scope on the Access Token that will be issued upon completion of the login flow.
   *
   * @param scope The scope to be removed.
   * @throws will throw an error if scope is invalid
   */
  removeScope(scope: string): void;
}

declare interface ChallengeWithOptions {
  additionalFactors?: FactorSelector[];
}
declare interface EnrollWithOptions {
  additionalFactors?: EnrollmentFactorSelector[];
}
declare interface AuthenticationAPI {
  /**
   * Request a challenge for multifactor authentication using the supplied factor and optional additional factors.
   *
   * When a multifactor challenge is requested, subsequent Actions will not be run until that challenge has been
   * fulfilled by the user. A user will have satisfied the challenge in any of the following situations:
   *
   * 1. They successfully complete the challenge for the default factor.
   * 2. They successfully complete the challenge for any of the optional factors described in `additionalFactors`.
   *
   * If any of the factors requested has already been challenged successfully in the current transaction, it will
   * be ignored.
   *
   * If a factor is requested is not enabled on the tenant, it will be ignored. If a factor is requested that the user
   * has not enrolled, it will be ignored. If none of the requested factors is enabled or enrolled, the authentication
   * transaction will fail (i.e. login will not complete).
   *
   * _**Note**: This method will result in a factor challenge screen being shown if the user has not already satisfied
   * the requirements of the challenge. If `additionalFactors` are supplied, the user will have the option to
   * select another factor if they choose to._
   *
   * @param factor An object describing the type of factor its options that should be used for the initial challenge.
   * @param options Additional options which can also specify `additionalFactors` as a property.
   */
  challengeWith(factor: FactorSelector, options?: ChallengeWithOptions): void;
  /**
   * Request a challenge for multifactor authentication using any of the supplied factors (showing a factor selection
   * screen first).
   *
   * When a multifactor challenge is requested, subsequent Actions will not be run until that challenge has been
   * fulfilled by the user. A user will have satisfied the challenge in any of the following situations:
   *
   * 1. They successfully complete the challenge for any of the factors.
   *
   * If any of the factors requested has already been challenged successfully in the current transaction, it will
   * be ignored.
   *
   * If a factor is requested is not enabled on the tenant, it will be ignored. If a factor is requested that the user
   * has not enrolled, it will be ignored. If none of the requested factors is enabled or enrolled, the authentication
   * transaction will fail (i.e. login will not complete).
   *
   * _**Note**: This method will result in the factor selector screen being shown if the user has not already satisfied
   * the requirements of the challenge. If there is a preferred factor, the `api.authentication.challengeWith()` method
   * is preferred. The factor selector screen will not be shown if only one factor is passed in or is valid._
   *
   * @param factors An array of factors.
   */
  challengeWithAny(factors: FactorSelector[]): void;
  /**
   * Request an enrollment for multifactor authentication using the supplied factor and optional additional factors.
   *
   * When a multifactor enrollment is requested, subsequent Actions will not be run until that enrollment has been
   * fulfilled by the user.
   *
   * If any of the factors requested has already been enrolled or challenged successfully in the current transaction, it will
   * be ignored.
   *
   * If a factor that is not enabled in the tenant is requested, it will be ignored.
   * If a factor that the user has already enrolled is requested, it will be ignored.
   * If none of the requested factors is enabled and not enrolled, the authentication
   * transaction will fail (i.e. login will not complete).
   *
   * @param factor An object describing the type of factor that should be used for the initial enrollment prompts and its options.
   * @param options Additional options which can also specify `additionalFactors` as a property.
   */
  enrollWith(factor: EnrollmentFactorSelector, options?: EnrollWithOptions): void;
  /**
   *
   * Request an enrollment for multifactor authentication using any of the supplied factors (showing a factor selection
   * screen first).
   *
   * When a multifactor enrollment is requested, subsequent Actions will not be run until that enrollment has been
   * fulfilled by the user.
   *
   * If any of the factors requested has already been enrolled successfully in the current transaction, it will
   * be ignored.
   *
   * If a factor that is not enabled in the tenant is requested, it will be ignored.
   * If a factor that the user has already enrolled is requested, it will be ignored.
   * If none of the requested factors is enabled and not enrolled, the authentication
   * transaction will fail (i.e. login will not complete).
   *
   * _**Note**: If there is a preferred factor, the `api.authentication.enrollWith()` method
   * is preferred. The factor selector screen will not be shown if only one factor is passed in or is valid._
   *
   * @param factors An array of additional factors.
   */
  enrollWithAny(factors: EnrollmentFactorSelector[]): void;
  /**
   * Indicate that a custom authentication method has been completed in the current
   * session. This method will then be available in the `event.authentication.methods`
   * array in subsequent logins.
   *
   * **IMPORTANT**: This API is only available from within the `onContinuePostLogin`
   * function for `PostLogin` Actions. In other words, this may be used to record the
   * completion of a custom authentication method after redirecting the user via
   * `api.redirect.sendUserTo()`.
   *
   * @param provider_url An `http:` or `https:` URL that uniquely represents the completed
   * authentication method.
   */
  recordMethod(provider_url: string): PostLoginAPI;
  /**
   * Change the primary user for the login transaction.
   *
   * In scenarios that require linking users, the user identity used to initiate the login may no longer
   * exist as a discrete user. That identity may now be a secondary identity of an existing user. In
   * such situations, the `setPrimaryUser()` function can be used to indicate that the subject of the
   * login should be changed.
   *
   * **IMPORTANT**: Insecurely linking accounts can allow malicious actors to access legitimate
   * user accounts.
   *
   * **IMPORTANT**: The identity used to authenticate the login _must_ be among the secondary identities
   * of the user referenced by `primary_user_id`. The login will fail and tokens will not be issued
   * otherwise.
   *
   * @param primary_user_id The user ID of the user for whom tokens should be issued (the `sub` claim).
   */
  setPrimaryUser(primary_user_id: string): void;
}

declare interface IdTokenAPI {
  /**
   * Set a custom claim on the ID Token that will be issued upon completion of the login flow.
   *
   * @param key Name of the claim (note that this may need to be a fully-qualified url).
   * @param value The value of the claim.
   */
  setCustomClaim(key: string, value: unknown): PostLoginAPI;
}

declare type DuoMultifactor = {
  provider: 'duo';
} & RequireMultifactorAuth;
declare interface EnableMultifactorOptions<T> {
  /**
   * When provider is set to `google-authenticator` or `duo`, the user is prompted for MFA once
   * every 30 days. When provider is set to `guardian`, the MFA prompt displays the enrollment
   * checkbox for users to choose whether or not to enroll. Defaults to `false`. To learn more,
   * read [Customize Multi-Factor Authentication Pages](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa).
   */
  allowRememberBrowser?: boolean;
  /**
   * Additional options to configure the challenge, only available for the `duo` provider.
   */
  providerOptions?: T extends 'duo' ? DuoMultifactor['providerOptions'] : never;
}
declare interface MultifactorAPI {
  /**
   * Enable multifactor authentication for this login flow. When enabled, users must complete the
   * configured multifactor challenge. The actual multifactor challenge will be deferred to the
   * end of the login flow.
   *
   * @param provider The name of the multifactor provider to use or the value `"any"` to use any
   * of the configured providers.
   * @param options Additional options for enabling multifactor challenges.
   */
  enable<T extends RequireMultifactorAuth['provider']>(
    provider: T,
    options?: EnableMultifactorOptions<T>
  ): PostLoginAPI;
}

declare interface PromptAPI {
  /**
   * Renders a custom prompt.
   *
   * @param promptId The prompt ID.
   * @param promptOptions The render options.
   */
  render(promptId: RenderPromptId, promptOptions?: RenderPromptOptions): void;
}

declare interface TokenCreationOptions {
  /**
   * Number of seconds before this token will expire
   *
   * @default 900 15 minutes.
   */
  expiresInSeconds?: number;
  /**
   * The data intended to be passed to the target of the redirect and whose authenticity
   * and integrity must be provable.
   */
  payload: {
    [key: string]: unknown;
  };
  /**
   * A secret that will be used to sign a JWT that is shared with the redirect target. The
   * secret value should be stored as a **secret** and retrieved using
   * `event.secrets['<secret_name>']`.
   */
  secret: string;
}
declare interface ValidateSessionTokenOptions {
  secret: string;
  /**
   * The name of the query or body parameter that was sent to the /continue endpoint.
   *
   * @default 'session_token'
   */
  tokenParameterName?: string;
}
declare interface SendUserToOptions {
  /**
   * An object representing additional query string parameters that should be appended to
   * the redirect URL.
   */
  query?: {
    [param: string]: string;
  };
}
declare interface RedirectAPI {
  /**
   * Create a session token suitable for using as a query string parameter redirect target (via `sendUserTo`)
   * that contains data whose authenticity must be provable by the target endpoint. The target endpoint
   * can verify the authenticity and integrity of the data by checking the JWT's signature
   * using a shared secret.
   *
   * The shared secret should be stored as a **secret** of the Action and will be readable at
   * `event.secrets['<secret_name>']`.
   *
   * @param options Configure how sensitive data is encoded into the query parameters of the
   * resulting url.
   *
   * @returns A JWT string.
   */
  encodeToken(options: TokenCreationOptions): string;
  /**
   * Cause the login pipeline to trigger a browser redirect to the target `url` immediately after
   * this action completes. The `createUrl` helper method is provided to simplify encoding
   * data as a query parameter in the target `url` such that the data's authenticity and
   * integrity can be verified by the target endpoint.
   *
   * @param baseUrl The url to which to redirect the user.
   */
  sendUserTo(url: string, options?: SendUserToOptions): PostLoginAPI;
  /**
   * Indicates if the current transaction is eligibile for a user redirect. Certain protocols such
   * as `oauth2-resource-owner`, `oauth2-refresh-token` do not support
   * redirecting the user. A request with `prompt=none` is also not eligible for a redirect.
   *
   * @deprecated The `canRedirect` method should not be relied upon to determine whether a
   * redirect is allowed or not in this flow. Instead, it is recommended that clients
   * appropriately handle any `interaction_required` errors arising from a redirect requested
   * in a non-interactive flow.
   *
   * @returns A boolean indicating if the current transaction is eligible for redirects.
   */
  canRedirect(): boolean;
  /**
   * Retrieve the data encoded in a JWT token passed to the `/continue` endpoint while verifying
   * the authenticity and integrity of that data.
   *
   * @param options Options for retrieving the data encoded in a JWT token passed to the
   * `/continue` endpoint following a rediret.
   *
   * @returns The payload of the JWT token.
   */
  validateToken(options: ValidateSessionTokenOptions): any;
}

declare interface RefreshTokenAPI {
  /**
   * [Enterprise Customers] Revoke the current user refresh token and mark the current refresh token exchange attempt as denied. This will prevent
   * the end-user from completing the refresh token exchange flow and revoke the currently used refresh token.
   * The refresh token exchange flow will immediately stop following the completion of this action and no further Actions will be executed.
   *
   * This method can be used only during Refresh Token Exchange flow, when `event.transaction.protocol === "oauth2-refresh-token"`.
   *
   * @param reason A human-readable explanation for rejecting the refresh token exchange. This may be presented
   * directly in end-user interfaces.
   */
  revoke(reason: string): void;
}

declare interface RulesAPI {
  /**
   * Check whether a Rule with a specific ID has been executed in the current transaction.
   *
   * @param ruleId The Rule ID.
   */
  wasExecuted(ruleId: string): boolean;
}

declare interface SAMLResponseAPI {
  /**
   * Set attributes on the SAML assertion being issued to the authenticated user.
   *
   * @param attribute The SAML attribute to be set.
   * @param value The value of the SAML claim. Setting this value to `null` or
   * `undefined` will remove the claim from the assertion.
   */
  setAttribute(attribute: string, value: SetSAMLAttributeValue): void;
  /**
   * Audience of the SAML assertion.
   * Default is issuer on SAMLRequest.
   */
  setAudience(audience: string): void;
  /**
   * Recipient of the SAML assertion (SubjectConfirmationData).
   * Default is AssertionConsumerUrl on SAMLRequest or callback URL if no SAMLRequest was sent.
   */
  setRecipient(recipient: string): void;
  /**
   * Whether or not a UPN claim should be created. Default is true.
   */
  setCreateUpnClaim(createUpnClaim: boolean): void;
  /**
   * If true (default), for each claim that is not mapped to the common profile, Auth0 passes through those in the output assertion.
   * If false, those claims won't be mapped.
   */
  setPassthroughClaimsWithNoMapping(passthroughClaimsWithNoMapping: boolean): void;
  /**
   * If passthroughClaimsWithNoMapping is true and this is false (default), for each claim not mapped to the common profile Auth0 adds a prefix http://schema.auth0.com.
   * If true it will pass through the claim as-is.
   */
  setMapUnknownClaimsAsIs(mapUnknownClaimsAsIs: boolean): void;
  /**
   * If true (default), it adds more information in the token such as the provider (Google, ADFS, AD, etc.) and the access token, if available.
   */
  setMapIdentities(mapIdentities: boolean): void;
  /**
   * Signature algorithm to sign the SAML assertion or response.
   * Default is rsa-sha256.
   */
  setSignatureAlgorithm(signatureAlgorithm: 'rsa-sha256'): void;
  /**
   * @deprecated Use rsa-sha256 instead, rsa-sha1 is not recommended.
   */
  setSignatureAlgorithm(signatureAlgorithm: 'rsa-sha1'): void;
  /**
   * Digest algorithm to calculate digest of the SAML assertion or response.
   * Default is sha256.
   */
  setDigestAlgorithm(digestAlgorithm: 'sha256'): void;
  /**
   * @deprecated Use 'sha256' instead, 'sha1' is not recommended.
   */
  setDigestAlgorithm(digestAlgorithm: 'sha1'): void;
  /**
   * Destination of the SAML response. If not specified, it will be AssertionConsumerUrl of SAMLRequest or callback URL if there was no SAMLRequest.
   */
  setDestination(destination: string): void;
  /**
   * Expiration of the token.
   * Default is 3600 seconds (1 hour).
   */
  setLifetimeInSeconds(lifetimeInSeconds: number): void;
  /**
   * Whether or not the SAML response should be signed.
   * By default the SAML assertion will be signed, but not the SAML response.
   * If true, SAML Response will be signed instead of SAML assertion.
   * Default to false.
   */
  setSignResponse(signResponse: boolean): void;
  /**
   * Default is urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified.
   */
  setNameIdentifierFormat(nameIdentifierFormat: string): void;
  /**
   * Auth0 will try each of the attributes of this array in order.
   * If one of them has a value, it will use that for the Subject/NameID.
   *
   * The order is:
   *   - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier (mapped from user_id),
   *   - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress (mapped from email),
   *   - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name (mapped from name).
   */
  setNameIdentifierProbes(nameIdentifierProbes: string[]): void;
  /**
   * Default is urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified.
   */
  setAuthnContextClassRef(authnContextClassRef: string): void;
  /**
   * Optionally indicates the public key certificate used to validate SAML requests.
   * If set, SAML requests will be required to be signed.
   * A sample value would be "-----BEGIN CERTIFICATE-----
MIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
[..all the other lines..]-----END CERTIFICATE-----
".
   */
  setSigningCert(signingCert: string): void;
  /**
   * When set to true, we infer the NameFormat based on the attribute name. NameFormat values are urn:oasis:names:tc:SAML:2.0:attrname-format:uri, urn:oasis:names:tc:SAML:2.0:attrname-format:basic and urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified.
   * If set to false, the attribute NameFormat is not set in the assertion.
   * Default is true.
   */
  setIncludeAttributeNameFormat(includeAttributeNameFormat: boolean): void;
  /**
   * When set to true, we infer the xs:type of the element. Types are xs:string, xs:boolean, xs:double and xs:anyType.
   * When set to false all xs:type are xs:anyType.
   * Default is true.
   */
  setTypedAttributes(typedAttributes: boolean): void;
  /**
   * Optionally specify a certificate used to encrypt the SAML assertion.
   * The certificate should be obtained from the service provider.
   * Both the certificate and public key must be specified.
   * A sample value would be "-----BEGIN CERTIFICATE-----
MIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
[..all the other lines..]-----END CERTIFICATE-----
".
   */
  setEncryptionCert(encryptionCert: string): void;
  /**
   * Optionally specify a public key used to encrypt the SAML assertion.
   * The public key should be obtained from the service provider.
   * Both the public key and certificate must be specified.
   * A sample value would be "-----BEGIN PUBLIC KEY-----
nMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
[..all the other lines..]-----END PUBLIC KEY-----
".
   */
  setEncryptionPublicKey(encryptionPublicKey: string): void;
  /**
   * By default, Auth0 will use the private/public key pair assigned to your tenant to sign SAML responses or assertions.
   * For very specific scenarios, you might wish to provide your own certificate and private key.
   *
   * Both the certificate and private key must be specified.
   * A sample value would be "-----BEGIN CERTIFICATE-----
MIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
[..all the other lines..]-----END CERTIFICATE-----
".
   */
  setCert(cert: string): void;
  /**
   * By default, Auth0 will use the private/public key pair assigned to your tenant to sign SAML responses or assertions.
   * For very specific scenarios, you might wish to provide your own certificate and private key.
   *
   * Since this private key is sensitive, **we recommend using the Add Secret functionality of Actions**.
   * See here for more details: https://auth0.com/docs/customize/actions/write-your-first-action#add-a-secret
   *
   * Both the certificate and private key must be specified.
   * A sample value would be "-----BEGIN PRIVATE KEY-----
nMIIC8jCCAdqgAwIBAgIJObB6jmhG0QIEMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
[..all the other lines..]-----END PRIVATE KEY-----
".
   */
  setKey(key: string): void;
  /**
   * Optionally specify a RelayState used to return to service provider
   */
  setRelayState(relayState: string): void;
  /**
   * Optionally specify the issuer of the SAML assertion.
   * Default is urn:auth0:TENANT
   */
  setIssuer(issuer: string): void;
}

declare interface SessionRevocationOptions {
  /** Default to false. If true, the system ends the session and keeps the refresh tokens. The application may continue to get access tokens for the duration of the refresh token lifetime. */
  preserveRefreshTokens?: boolean;
}
declare interface SessionAPI {
  /**
   * [Enterprise Customers] Revoke the current user session and mark the current login attempt as denied. This will prevent
   * the end-user from completing the login flow and revoke their session. The login flow will immediately
   * stop following the completion of this action and no further Actions will be executed.
   *
   * @param reason A human-readable explanation for rejecting the login. This may be presented
   * directly in end-user interfaces.
   *
   * @param options
   */
  revoke(reason: string, options?: SessionRevocationOptions): void;
}

declare interface UserAPI {
  /**
   * Set application-specific metadata for the user that is logging in.
   *
   * Note: This method should not be used in callbacks. Invoking this method won't update the metadata immediately.
   * You can call this several times throughout multiple actions of the same flow and the engine will aggregate the
   * changes and update the metadata at once before the flow is completed. This function works only with metadata that
   * are in the object format.
   *
   * @param key The metadata property to be set.
   * @param value The value of the metadata property. This may be set to `null` to remove the
   * metadata property.
   */
  setAppMetadata(key: string, value: unknown): PostLoginAPI;
  /**
   * Set general metadata for the user that is logging in.
   *
   * Note: This method should not be used in callbacks. Invoking this method won't update the metadata immediately.
   * You can call this several times throughout multiple actions of the same flow and the engine will aggregate the
   * changes and update the metadata at once before the flow is completed. This function works only with metadata that
   * are in the object format.
   *
   * @param key The metadata property to be set.
   * @param value The value of the metadata property. This may be set to `null` to remove the
   * metadata property.
   */
  setUserMetadata(key: string, value: unknown): PostLoginAPI;
}

/**
 * Methods and utilities to help change the behavior of the login flow.
 */
declare interface PostLoginAPI {
  /**
   * Modify the access of the user that is logging in, such as rejecting the login attempt.
   */
  readonly access: AccessAPI;
  /**
   * Request changes to the access token being issued.
   */
  readonly accessToken: AccessTokenAPI;
  /**
   * Request changes to the authentication state of the current user's session.
   */
  readonly authentication: AuthenticationAPI;
  /**
   * Request changes to the ID token being issued.
   */
  readonly idToken: IdTokenAPI;
  /**
   * Set or remove the requirement for multifactor authentication on the login attempt.
   */
  readonly multifactor: MultifactorAPI;
  /**
   * Configure and initiate external redirects.
   */
  readonly redirect: RedirectAPI;
  /**
   * Make changes to the metadata of the user that is logging in.
   */
  readonly user: UserAPI;
  /**
   * Make changes to the cache.
   */
  readonly cache: CacheAPI;
  /**
   * Configure custom SAML configurations and attributes.
   */
  readonly samlResponse: SAMLResponseAPI;
  /**
   * Prevent user from logging in by throwing a validation error.
   */
  readonly validation: ValidationAPI;
  /**
   * Identify if a rule has been executed in the current transaction.
   */
  readonly rules: RulesAPI;
  /**
   * Renders a custom prompt.
   */
  readonly prompt: PromptAPI;
}

declare interface PostLoginAction {
  (event: TEvent, api: PostLoginAPI): void;
}

declare interface RefreshTokenAPI {
  /**
   * [Enterprise Customers] Sets a new absolute expiration time for the current refresh token
   * The expiration cannot be set higher than the maximum absolute refresh token lifetime set in the settings.
   * When called multiple times - the earliest expiration time will be used.
   *
   * @param absolute Required, the new absolute expiration time.
   */
  setExpiresAt(absolute: number): void;

  /**
   * [Enterprise Customers] Sets a new idle expiration time for the current refresh token.
   * The expiration cannot be set higher than the maximum absolute refresh token lifetime set in the settings.
   * When called multiple times - the earliest expiration time will be used.
   *
   * @param idle Required, the new idle expiration time.
   */
  setIdleExpiresAt(idle: number): void;
}
declare interface SessionAPI {
  /**
   * [Enterprise Customers] Sets a new absolute expiration time for the current session
   * The expiration cannot be set higher than the maximum absolute session lifetime set in the settings.
   * When called multiple times - the earliest expiration time will be used.
   *
   * @param absolute Required, the new absolute expiration time.
   */
  setExpiresAt(absolute: number): void;

  /**
   * [Enterprise Customers] Sets a new idle expiration time for the current session.
   * The expiration cannot be set higher than the maximum absolute session lifetime set in the settings.
   * When called multiple times - the earliest expiration time will be used.
   *
   * @param idle Required, the new idle expiration time.
   */
  setIdleExpiresAt(idle: number): void;
}
declare interface PostLoginAPI {
  readonly session: SessionAPI;
}
declare interface PostLoginAPI {
  readonly refreshToken: RefreshTokenAPI;
}
declare type PostLoginEvent = TEvent;
