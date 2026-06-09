export function analyzeFormFields(fields) {
  const hasPassword = fields.some((f) => f.type === 'password' || /pass/i.test(f.name || f.id || ''));
  const hasCreditCard = fields.some((f) =>
    /card|cc-num|credit/i.test(f.name || f.id || f.autocomplete || '')
  );
  const hasOtp = fields.some((f) =>
    /otp|one-time|verification.code|2fa|mfa/i.test(f.name || f.id || f.autocomplete || '')
  );
  const hasLogin = hasPassword || fields.some((f) =>
    /user|email|login|signin/i.test(f.name || f.id || f.autocomplete || '')
  );

  const formType = hasCreditCard ? 'credit_card' : hasOtp ? 'otp' : hasPassword ? 'login' : hasLogin ? 'login' : 'generic';

  return {
    formType,
    hasPassword,
    hasCreditCard,
    hasOtp,
    hasLogin,
    fieldCount: fields.length,
    isCredentialForm: hasPassword || hasCreditCard || hasOtp
  };
}

export function processFormDetection(message) {
  const analysis = analyzeFormFields(message.fields || []);
  return {
    event: 'credential_form_detected',
    timestamp: message.timestamp,
    domain: message.domain,
    url: message.url,
    pageTitle: message.pageTitle,
    ...analysis
  };
}
