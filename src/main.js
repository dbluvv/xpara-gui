const { invoke } = window.__TAURI__.core;

let currentWallet = null;

async function loadWallet(password = "") {
  try {
    const loginButton = document.getElementById("login-btn");
    if (loginButton) loginButton.disabled = false;

    currentWallet = await invoke("get_wallet", { password });

    const addressElement = document.getElementById("wallet-address");
    if (addressElement && currentWallet) {
      addressElement.textContent = currentWallet.address;
    }

    if (document.getElementById("public-key") && currentWallet) {
      document.getElementById("public-key").textContent = currentWallet.public_key;
      document.getElementById("secret-key").textContent = currentWallet.secret_key;
      document.getElementById("address").textContent = currentWallet.address;
    }
	
	if (document.getElementById("current-address") && currentWallet) {
		document.getElementById("current-address").textContent = currentWallet.address;
	}

    return currentWallet;
  } catch (error) {
    const loginButton = document.getElementById("login-btn");
    if (loginButton) loginButton.disabled = true;

    const addressElement = document.getElementById("wallet-address");
    if (addressElement) {
      addressElement.textContent = "Click on 'SELECT WALLET' to choose an existing wallet or create a new one";
    }

    console.error("Error loading wallet:", error);
    return null;
  }
}

async function handleLogin() {
  const passwordInput = document.getElementById("wallet-password");
  const password = passwordInput ? passwordInput.value : "";

  const wallet = await loadWallet(password);

  if (wallet) {
    window.location.href = "xpara.html";
  } else {
    alert("Incorrect password or wallet not selected.");
  }
}

function setupNavigation() {
  const loginBtn = document.getElementById("login-btn");
  if (loginBtn) loginBtn.addEventListener("click", handleLogin);

  const viewKeysBtn = document.getElementById("view-keys-btn");
  if (viewKeysBtn) viewKeysBtn.addEventListener("click", () => {
    window.location.href = "keys.html";
  });

  const upowBtn = document.getElementById("upow-mining-btn");
  if (upowBtn) upowBtn.addEventListener("click", () => {
    window.location.href = "upow.html";
  });

  const rngBtn = document.getElementById("rng-population-btn");
  if (rngBtn) rngBtn.addEventListener("click", () => {
    window.location.href = "rng.html";
  });

  const oracleBtn = document.getElementById("oracle-services-btn");
  if (oracleBtn) oracleBtn.addEventListener("click", () => {
    window.location.href = "oracle.html";
  });

  const sendBtn = document.getElementById("send-btn");
  if (sendBtn) sendBtn.addEventListener("click", () => {
    window.location.href = "send.html";
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  await loadWallet();
  setupNavigation();
});
