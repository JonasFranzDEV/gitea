// This "library" is inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/index.html

export function isSupported() {
  return !(window.PublicKeyCredential === undefined ||
    typeof window.PublicKeyCredential !== "function");

}


// Base64 to ArrayBuffer
function bufferDecode(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export async function createCredentials(options) {
  delete options.publicKey.rp.id;
  options.publicKey.challenge = bufferDecode(options.publicKey.challenge);
  options.publicKey.user.id = bufferDecode(options.publicKey.user.id);
  if (options.publicKey.excludeCredentials) {
    for (let i = 0; i < options.publicKey.excludeCredentials.length; i++) {
      options.publicKey.excludeCredentials[i].id = bufferDecode(options.publicKey.excludeCredentials[i].id);
    }
  }

  console.log(options.publicKey);

  const credential = await navigator.credentials.create({
    publicKey: options.publicKey
  });

  return {
    id: credential.id,
    rawId: bufferEncode(credential.id),
    type: credential.type,
    response: {
      attestationObject: bufferEncode(credential.response.attestationObject),
      clientDataJSON: bufferEncode(credential.response.clientDataJSON),
    }
  };
}

export async function signChallenge(challenge) {
  challenge.publicKey.challenge = bufferDecode(challenge.publicKey.challenge);
  challenge.publicKey.allowCredentials.forEach(function (listItem) {
    listItem.id = bufferDecode(listItem.id)
  });
  const assertion = await navigator.credentials.get({
    publicKey: challenge.publicKey,
  });
  console.log(assertion);
  let authData = assertion.response.authenticatorData;
  let clientDataJSON = assertion.response.clientDataJSON;
  let rawId = assertion.rawId;
  let sig = assertion.response.signature;
  let userHandle = assertion.response.userHandle;

  return {
    id: assertion.id,
    rawId: bufferEncode(rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferEncode(authData),
      clientDataJSON: bufferEncode(clientDataJSON),
      signature: bufferEncode(sig),
      userHandle: bufferEncode(userHandle),
    }
  }
}
