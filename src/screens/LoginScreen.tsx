import React from 'react';
import { View, Text, Pressable, StyleSheet, KeyboardAvoidingView, Platform, Image, ScrollView, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import Constants from 'expo-constants';
import { ChevronDown, ChevronUp, Eye, EyeOff, X, QrCode } from 'lucide-react-native';
import { spacing, typography, type ThemePalette } from '../theme/tokens';
import { useColors } from '../theme/colors';
import { Button, Input, RadioGroup } from '../components';
import { QrScanModal } from '../components/QrScanModal';
import { parseQrLoginPayload } from '../lib/oauth';
import { useAuthStore } from '../stores/auth-store';

const APP_VERSION = Constants.expoConfig?.version ?? '0.0.0';

type AuthMode = 'basic' | 'oauth' | 'webmail' | 'qrcode';

interface LoginScreenProps {
  onLogin?: () => void;
  isAddMode?: boolean;
  onCancel?: () => void;
}

export default function LoginScreen({ onLogin, isAddMode, onCancel }: LoginScreenProps) {
  const c = useColors();
  const styles = React.useMemo(() => makeStyles(c), [c]);
  const login = useAuthStore((state) => state.login);
  const loginViaWebmail = useAuthStore((state) => state.loginViaWebmail);
  const loginViaPairing = useAuthStore((state) => state.loginViaPairing);
  const basicLogin = useAuthStore((state) => state.basicLogin);
  const oauthLogin = useAuthStore((state) => state.oauthLogin);
  const discoveryLogin = useAuthStore((state) => state.discoveryLogin);
  const isLoading = useAuthStore((state) => state.isLoading);
  const error = useAuthStore((state) => state.error);
  const clearError = useAuthStore((state) => state.clearError);

  const [serverUrl, setServerUrl] = React.useState('');
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [showPassword, setShowPassword] = React.useState(false);
  const [scannerVisible, setScannerVisible] = React.useState(false);
  const [advancedOpen, setAdvancedOpen] = React.useState(false);
  const [authMode, setAuthMode] = React.useState<AuthMode>('basic');
  const [issuerUrl, setIssuerUrl] = React.useState('');
  const [clientId, setClientId] = React.useState('');
  const [clientSecret, setClientSecret] = React.useState('');

  const trimmedEmail = email.trim();
  const trimmedServerUrl = serverUrl.trim();
  const trimmedIssuerUrl = issuerUrl.trim();

  const canDiscover = trimmedEmail.includes('@') && trimmedEmail.lastIndexOf('@') < trimmedEmail.length - 1;
  const canBasicLogin = Boolean(trimmedServerUrl && trimmedEmail && password);
  const canOauthLogin = Boolean(trimmedServerUrl && trimmedIssuerUrl);
  const canHandoff = Boolean(trimmedServerUrl);

  const handleBasicLogin = async () => {
    if (!canBasicLogin) return;
    try {
      await basicLogin(trimmedServerUrl, trimmedEmail, password, { addAccount: isAddMode });
      onLogin?.();
    } catch {
      // Store carries the user-facing error.
    }
  };

  const handleOauth = async () => {
    if (!canOauthLogin) return;
    const before = useAuthStore.getState().isAuthenticated;
    try {
      await oauthLogin(
        {
          jmapServerUrl: trimmedServerUrl,
          issuerUrl: trimmedIssuerUrl,
          clientId: clientId.trim() || undefined,
          clientSecret: clientSecret.trim() || undefined,
        },
        { addAccount: isAddMode },
      );
      const after = useAuthStore.getState().isAuthenticated;
      if (after && (!before || isAddMode)) onLogin?.();
    } catch {
      // Store carries the user-facing error.
    }
  };

  const handleDiscoveryLogin = async () => {
    if (!canDiscover) return;
    const before = useAuthStore.getState().isAuthenticated;
    try {
      await discoveryLogin(trimmedEmail, { addAccount: isAddMode });
      const after = useAuthStore.getState().isAuthenticated;
      if (after && (!before || isAddMode)) onLogin?.();
    } catch {
      // Store carries the user-facing error.
    }
  };

  const handleWebmailHandoff = async () => {
    if (!canHandoff) return;
    try {
      const before = useAuthStore.getState().isAuthenticated;
      await loginViaWebmail(serverUrl.trim(), { addAccount: isAddMode });
      // loginViaWebmail swallows the "user cancelled the browser" case
      // silently — only fire the navigation hook when authentication
      // actually completed.
      const after = useAuthStore.getState().isAuthenticated;
      if (after && !before) {
        onLogin?.();
      } else if (isAddMode && after) {
        onLogin?.();
      }
    } catch {
      // Store state already contains the user-facing error.
    }
  };

  const handleScanned = async (data: string) => {
    setScannerVisible(false);
    const payload = parseQrLoginPayload(data);
    if (!payload) {
      Alert.alert('Unrecognized QR code', "That QR code isn't a Bulwark Mail sign-in code.");
      return;
    }
    try {
      const before = useAuthStore.getState().isAuthenticated;
      if (payload.kind === 'connect') {
        // Server-bootstrap QR: fill the field and run the normal browser
        // handoff so the user still authenticates in the webmail.
        setServerUrl(payload.webmailUrl);
        await loginViaWebmail(payload.webmailUrl, { addAccount: isAddMode });
      } else {
        // Cross-device pairing QR: redeem the one-time code for tokens, no
        // browser round-trip needed.
        await loginViaPairing(payload.webmailUrl, payload.code, { addAccount: isAddMode });
      }
      const after = useAuthStore.getState().isAuthenticated;
      if ((after && !before) || (isAddMode && after)) {
        onLogin?.();
      }
    } catch {
      // Store state already contains the user-facing error.
    }
  };

  const updateField = React.useCallback(
    (setter: React.Dispatch<React.SetStateAction<string>>) => (value: string) => {
      if (useAuthStore.getState().error) {
        clearError();
      }
      setter(value);
    },
    [clearError],
  );

  const onChangeEmail = React.useMemo(() => updateField(setEmail), [updateField]);
  const onChangeServerUrl = React.useMemo(() => updateField(setServerUrl), [updateField]);
  const onChangePassword = React.useMemo(() => updateField(setPassword), [updateField]);
  const onChangeIssuerUrl = React.useMemo(() => updateField(setIssuerUrl), [updateField]);
  const onChangeClientId = React.useMemo(() => updateField(setClientId), [updateField]);
  const onChangeClientSecret = React.useMemo(() => updateField(setClientSecret), [updateField]);

  const primaryDisabled = !canDiscover || isLoading;

  return (
    <SafeAreaView style={styles.container}>
      {isAddMode && onCancel ? (
        <Pressable onPress={onCancel} style={styles.cancelButton} hitSlop={10}>
          <X size={24} color={c.text} />
        </Pressable>
      ) : null}
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardView}
      >
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          {/* Logo & Branding */}
          <View style={styles.branding}>
            <View style={styles.logoContainer}>
              <Image
                source={require('../../assets/logos/Bulwark Logo White.png')}
                style={styles.logoImage}
                resizeMode="contain"
              />
            </View>
            <Text style={styles.appName}>{isAddMode ? 'Add account' : 'Bulwark Mail'}</Text>
            <Text style={styles.tagline}>
              {isAddMode ? 'Sign in to a second account' : 'Secure. Private. Yours.'}
            </Text>
          </View>

          {/* Default form — email-only auto-discovery */}
          <View style={styles.form}>
            <Input
              label="Email"
              placeholder="you@example.com"
              value={email}
              onChangeText={onChangeEmail}
              autoCapitalize="none"
              keyboardType="email-address"
              autoCorrect={false}
              onSubmitEditing={() => {
                void handleDiscoveryLogin();
              }}
            />

            <Button
              variant="default"
              size="lg"
              onPress={() => {
                void handleDiscoveryLogin();
              }}
              disabled={primaryDisabled}
              loading={isLoading}
              style={styles.loginButton}
            >
              {isLoading ? 'Signing in...' : 'Sign In'}
            </Button>

            {error ? <Text style={styles.errorText}>{error}</Text> : null}

            {/* Advanced toggle */}
            <Pressable onPress={() => setAdvancedOpen((v) => !v)} style={styles.advancedToggle} hitSlop={8}>
              <Text style={styles.advancedToggleText}>Advanced settings</Text>
              {advancedOpen ? (
                <ChevronUp size={16} color={c.textMuted} />
              ) : (
                <ChevronDown size={16} color={c.textMuted} />
              )}
            </Pressable>

            {/* advanced login options */}
            {advancedOpen ? (
              <View style={styles.advanced}>
                <View>
                  <Text style={styles.fieldLabel}>Authentication</Text>
                  <RadioGroup
                    options={[
                      { label: 'Basic', value: 'basic' },
                      { label: 'OAuth', value: 'oauth' },
                      { label: 'Webmail', value: 'webmail' },
                      { label: 'Scan QR code', value: 'qrcode' },
                    ]}
                    value={authMode}
                    onChange={(v) => setAuthMode(v as AuthMode)}
                  />
                </View>
                {authMode === 'webmail' ? (
                  <>
                    <Input
                      label="Webmail URL"
                      placeholder="https://webmail.example.com"
                      value={serverUrl}
                      onChangeText={onChangeServerUrl}
                      autoCapitalize="none"
                      keyboardType="url"
                      autoCorrect={false}
                    />
                    <Button
                      variant="outline"
                      size="md"
                      onPress={() => {
                        void handleWebmailHandoff();
                      }}
                      disabled={!canHandoff || isLoading}
                    >
                      Sign in via webmail
                    </Button>
                  </>
                ) : authMode === 'qrcode' ? (
                  <Button
                    variant="ghost"
                    size="md"
                    onPress={() => setScannerVisible(true)}
                    disabled={isLoading}
                    icon={<QrCode size={18} color={c.text} />}
                  >
                    Scan QR code
                  </Button>
                ) : authMode === 'basic' ? (
                  <>
                    <Input
                      label="JMAP server URL"
                      placeholder="https://mail.example.com"
                      value={serverUrl}
                      onChangeText={onChangeServerUrl}
                      autoCapitalize="none"
                      keyboardType="url"
                      autoCorrect={false}
                    />
                    <Input
                      label="Login"
                      placeholder="you@example.com"
                      value={email}
                      onChangeText={onChangeEmail}
                      autoCapitalize="none"
                      keyboardType="email-address"
                      autoCorrect={false}
                    />
                    <Input
                      label="Password"
                      placeholder="Enter your password"
                      value={password}
                      onChangeText={onChangePassword}
                      secureTextEntry={!showPassword}
                      onSubmitEditing={() => {
                        void handleBasicLogin();
                      }}
                      rightIcon={
                        <Pressable onPress={() => setShowPassword(!showPassword)}>
                          {showPassword ? (
                            <EyeOff size={20} color={c.textMuted} />
                          ) : (
                            <Eye size={20} color={c.textMuted} />
                          )}
                        </Pressable>
                      }
                    />
                    <Button
                      variant="default"
                      size="lg"
                      onPress={() => {
                        void handleBasicLogin();
                      }}
                      disabled={isLoading || !canBasicLogin}
                      loading={isLoading}
                      style={styles.loginButton}
                    >Sign in with password</Button>
                  </>
                ) : (
                  <>
                    <Input
                      label="JMAP server URL"
                      placeholder="https://mail.example.com"
                      value={serverUrl}
                      onChangeText={onChangeServerUrl}
                      autoCapitalize="none"
                      keyboardType="url"
                      autoCorrect={false}
                    />
                    <Input
                      label="Issuer URL"
                      placeholder="https://idp.example.com"
                      value={issuerUrl}
                      onChangeText={onChangeIssuerUrl}
                      autoCapitalize="none"
                      keyboardType="url"
                      autoCorrect={false}
                    />
                    <Input
                      label="Client ID"
                      placeholder="bulwark-android"
                      value={clientId}
                      onChangeText={onChangeClientId}
                      autoCapitalize="none"
                      autoCorrect={false}
                    />
                    <Input
                      label="Client secret (optional)"
                      placeholder="Leave empty for public clients"
                      value={clientSecret}
                      onChangeText={onChangeClientSecret}
                      secureTextEntry
                      autoCapitalize="none"
                      autoCorrect={false}
                    />
                    <Button
                      variant="default"
                      size="lg"
                      onPress={() => {
                        void handleOauth();
                      }}
                      disabled={isLoading || !canOauthLogin}
                      loading={isLoading}
                      style={styles.loginButton}
                    >Sign in with OAuth</Button>
                  </>
                )}
              </View>
            ) : null}
          </View>

          {/* Footer */}
          <View style={styles.footer}>
            <Text style={styles.footerText}>Bulwark Mobile v{APP_VERSION}</Text>
            <Text style={styles.footerLink}>Privacy Policy</Text>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>

      <QrScanModal
        visible={scannerVisible}
        onClose={() => setScannerVisible(false)}
        onScanned={(data) => {
          void handleScanned(data);
        }}
      />
    </SafeAreaView>
  );
}

function makeStyles(c: ThemePalette) {
  return StyleSheet.create({
    container: { flex: 1, backgroundColor: c.background },
    cancelButton: {
      position: 'absolute',
      top: 50,
      left: 16,
      zIndex: 10,
      padding: 8,
    },
    keyboardView: { flex: 1 },
    content: {
      flexGrow: 1,
      justifyContent: 'center',
      paddingHorizontal: spacing.xxl,
      paddingVertical: spacing.xl,
    },
    branding: { alignItems: 'center', marginBottom: 40 },
    logoContainer: {
      width: 80,
      height: 80,
      alignItems: 'center',
      justifyContent: 'center',
      marginBottom: spacing.lg,
    },
    logoImage: { width: 72, height: 72 },
    appName: { ...typography.h1, color: c.text },
    tagline: { ...typography.caption, color: c.textMuted, marginTop: spacing.xs },

    form: { gap: spacing.lg },
    loginButton: { marginTop: spacing.sm },
    errorText: { ...typography.caption, color: c.error, textAlign: 'center' },

    advancedToggle: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'center',
      gap: spacing.xs,
      marginTop: spacing.md,
      paddingVertical: spacing.sm,
    },
    advancedToggleText: { ...typography.caption, color: c.textMuted },
    advanced: {
      gap: spacing.lg,
      paddingTop: spacing.md,
      borderTopWidth: 1,
      borderTopColor: c.border,
    },
    fieldLabel: {
      ...typography.caption,
      color: c.textMuted,
      marginBottom: spacing.xs,
    },

    footer: { alignItems: 'center', marginTop: 40, gap: spacing.xs },
    footerText: { ...typography.caption, color: c.textMuted },
    footerLink: { ...typography.caption, color: c.textLink },
  });
}
