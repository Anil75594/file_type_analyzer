const fileInput = document.getElementById("fileInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const hint = document.getElementById("hint");

const resultSection = document.getElementById("result");
const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");

const fileNameEl = document.getElementById("fileName");
const extensionEl = document.getElementById("extension");
const expectedExtensionsEl = document.getElementById("expectedExtensions");
const actualTypeEl = document.getElementById("actualType");
const fileSizeEl = document.getElementById("fileSize");
const md5El = document.getElementById("md5");
const sha256El = document.getElementById("sha256");
const signatureHexEl = document.getElementById("signatureHex");

function setHint(message, isError = false) {
  hint.textContent = message || "";
  hint.classList.toggle("error", Boolean(isError));
}

function setLoading(isLoading) {
  analyzeBtn.disabled = isLoading;
  analyzeBtn.textContent = isLoading ? "Analyzing..." : "Analyze File";
}

function hideResult() {
  resultSection.classList.add("hidden");
}

function showResult() {
  resultSection.classList.remove("hidden");
}

function formatKB(kb) {
  if (typeof kb !== "number" || Number.isNaN(kb)) return "";
  return `${kb} KB`;
}

function renderResult(data) {
  fileNameEl.textContent = data.file_name ?? "";
  extensionEl.textContent = data.extension ?? "";
  const expected = Array.isArray(data.expected_extensions) ? data.expected_extensions : [];
  expectedExtensionsEl.textContent = expected.length ? expected.map((e) => `.${e}`).join(", ") : "(n/a)";
  actualTypeEl.textContent = data.actual_type ?? "";
  fileSizeEl.textContent = formatKB(data.file_size_kb);
  md5El.textContent = data.md5 ?? "";
  sha256El.textContent = data.sha256 ?? "";
  signatureHexEl.textContent = data.signature_hex ?? "";

  const suspicious = Boolean(data.suspicious);
  const status = data.status ?? (suspicious ? "Suspicious file detected" : "Safe file");
  const reason = data.reason ? ` ${data.reason}` : "";

  statusBadge.classList.remove("ok", "warn");
  statusText.classList.remove("ok", "warn");

  if (suspicious) {
    statusBadge.textContent = "⚠️ Suspicious";
    statusBadge.classList.add("warn");
    statusText.textContent = `${status}${reason}`;
    statusText.classList.add("warn");
  } else {
    statusBadge.textContent = "✅ Safe";
    statusBadge.classList.add("ok");
    statusText.textContent = `${status}${reason}`;
    statusText.classList.add("ok");
  }

  showResult();
}

async function analyzeFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const resp = await fetch("/analyze", {
    method: "POST",
    body: formData,
  });

  let payload = null;
  try {
    payload = await resp.json();
  } catch {
    // ignore
  }

  if (!resp.ok) {
    const message = payload?.error || `Request failed (${resp.status})`;
    throw new Error(message);
  }

  return payload;
}

analyzeBtn.addEventListener("click", async () => {
  hideResult();
  setHint("");

  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    setHint("Please select a file first.", true);
    return;
  }

  setLoading(true);
  setHint("Uploading file and analyzing magic number + hashes...");

  try {
    const data = await analyzeFile(file);
    setHint("");
    renderResult(data);
  } catch (err) {
    setHint(err?.message || "Something went wrong.", true);
  } finally {
    setLoading(false);
  }
});

