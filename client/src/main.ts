import './style.css';
import { deriveKeys, encrypt, decrypt, Keys } from './lib/crypto';

const API_URL = 'http://localhost:3000/api';

interface State {
  token: string | null;
  keys: Keys | null;
  items: any[];
  user: string | null;
}

let state: State = {
  token: localStorage.getItem('token'),
  keys: null,
  items: [],
  user: localStorage.getItem('user'),
};

const app = document.querySelector<HTMLDivElement>('#app')!;

async function init() {
  if (state.token && state.user) {
    // We need keys to decrypt! Since keys are memory-only, 
    // we need to ask for the password again or keep it in session storage (less secure).
    // For this demo, if token exists but no keys, go to login.
    renderLogin();
  } else {
    renderLogin();
  }
}

function renderLogin() {
  app.innerHTML = `
    <div class="auth-container">
      <h1>ZK-Vault</h1>
      <p>Zero-knowledge storage for your secrets.</p>
      <br/>
      <div id="auth-form">
        <div class="input-group">
          <label>Username</label>
          <input type="text" id="username" placeholder="Seu usuário" />
        </div>
        <div class="input-group">
          <label>Password</label>
          <input type="password" id="password" placeholder="Sua senha mestre" />
        </div>
        <div style="display: flex; gap: 1rem;">
          <button id="login-btn">Login</button>
          <button id="register-btn" style="background: transparent; border: 1px solid var(--accent-color); color: var(--accent-color);">Register</button>
        </div>
        <div id="auth-error" style="color: #ff4d4d; margin-top: 1rem; font-size: 0.9rem;"></div>
      </div>
    </div>
  `;

  document.querySelector('#login-btn')?.addEventListener('click', handleLogin);
  document.querySelector('#register-btn')?.addEventListener('click', handleRegister);
}

async function handleLogin() {
  const username = (document.querySelector('#username') as HTMLInputElement).value;
  const password = (document.querySelector('#password') as HTMLInputElement).value;
  const errorEl = document.querySelector('#auth-error')!;

  try {
    errorEl.textContent = 'Derivando chaves (Argon2)...';
    
    // 1. Get salt
    const saltRes = await fetch(`${API_URL}/auth/salt/${username}`);
    const { salt } = await saltRes.json();

    // 2. Derive keys
    const keys = await deriveKeys(password, salt);

    // 3. Login with authKey
    const loginRes = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, authKey: keys.authKey }),
    });

    const data = await loginRes.json();
    if (data.error) throw new Error(data.error);

    state.token = data.token;
    state.keys = keys;
    state.user = username;
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', username);

    renderDashboard();
  } catch (err: any) {
    errorEl.textContent = err.message;
  }
}

async function handleRegister() {
  const username = (document.querySelector('#username') as HTMLInputElement).value;
  const password = (document.querySelector('#password') as HTMLInputElement).value;
  const errorEl = document.querySelector('#auth-error')!;

  try {
    errorEl.textContent = 'Gerando chaves de alta segurança...';
    
    const salt = Array.from(window.crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const keys = await deriveKeys(password, salt);

    const regRes = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, salt, authKey: keys.authKey }),
    });

    const data = await regRes.json();
    if (data.error) throw new Error(data.error);

    state.token = data.token;
    state.keys = keys;
    state.user = username;
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', username);

    renderDashboard();
  } catch (err: any) {
    errorEl.textContent = err.message;
  }
}

async function renderDashboard() {
  app.innerHTML = `
    <div class="vault-header">
      <h1>My Vault</h1>
      <div style="display: flex; gap: 1rem; align-items: center;">
        <span>User: <strong>${state.user}</strong></span>
        <button id="logout-btn" style="width: auto; padding: 0.5rem 1rem;">Sair</button>
      </div>
    </div>

    <div style="margin-bottom: 2rem;">
      <button id="add-item-btn" style="width: auto;">+ New Secret</button>
    </div>

    <div class="vault-grid" id="vault-grid">
      <div class="loader"></div>
    </div>

    <div id="modal-container"></div>
  `;

  document.querySelector('#logout-btn')?.addEventListener('click', logout);
  document.querySelector('#add-item-btn')?.addEventListener('click', showAddModal);

  await fetchAndDecryptItems();
}

async function fetchAndDecryptItems() {
  const grid = document.querySelector('#vault-grid')!;
  
  try {
    const res = await fetch(`${API_URL}/vault`, {
      headers: { 'Authorization': `Bearer ${state.token}` },
    });
    const items = await res.json();
    
    if (items.length === 0) {
      grid.innerHTML = '<p>Seu cofre está vazio. Adicione um segredo!</p>';
      return;
    }

    grid.innerHTML = '';
    
    for (const item of items) {
      const decryptedTitle = await decrypt(item.title, item.nonce, state.keys!.encryptionKey);
      const decryptedData = await decrypt(item.data, item.nonce, state.keys!.encryptionKey);
      
      const card = document.createElement('div');
      card.className = 'vault-card';
      card.innerHTML = `
        <h3>${decryptedTitle}</h3>
        <p>${decryptedData}</p>
        <button class="delete-btn" data-id="${item.id}">Excluir</button>
      `;
      grid.appendChild(card);
    }

    document.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = (e.target as HTMLElement).dataset.id!;
        deleteItem(id);
      });
    });

  } catch (err) {
    grid.innerHTML = '<p style="color: #ff4d4d;">Erro ao carregar dados.</p>';
  }
}

function showAddModal() {
  const modalContainer = document.querySelector('#modal-container')!;
  modalContainer.innerHTML = `
    <div class="modal-overlay">
      <div class="modal">
        <h2>Adicionar Segredo</h2>
        <br/>
        <div class="input-group">
          <label>Título</label>
          <input type="text" id="new-title" placeholder="ex: Senha do Banco" />
        </div>
        <div class="input-group">
          <label>Conteúdo</label>
          <input type="text" id="new-data" placeholder="Sua informação secreta" />
        </div>
        <div style="display: flex; gap: 1rem;">
          <button id="save-item-btn">Salvar</button>
          <button id="cancel-btn" style="background: #333; color: white;">Cancelar</button>
        </div>
      </div>
    </div>
  `;

  document.querySelector('#cancel-btn')?.addEventListener('click', () => modalContainer.innerHTML = '');
  document.querySelector('#save-item-btn')?.addEventListener('click', saveItem);
}

async function saveItem() {
  const title = (document.querySelector('#new-title') as HTMLInputElement).value;
  const data = (document.querySelector('#new-data') as HTMLInputElement).value;
  
  if (!title || !data) return;

  const btn = document.querySelector('#save-item-btn') as HTMLButtonElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="loader"></span> Criptografando...';

  try {
    const encryptedTitle = await encrypt(title, state.keys!.encryptionKey);
    const encryptedData = await encrypt(data, state.keys!.encryptionKey);

    // Note: title and data must share the same nonce for simplicity, or separate ones.
    // Our encrypt function generates a new nonce each time.
    // Let's re-encrypt with a single nonce for the item record.
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const finalTitle = await encryptWithNonce(title, state.keys!.encryptionKey, nonce);
    const finalData = await encryptWithNonce(data, state.keys!.encryptionKey, nonce);

    await fetch(`${API_URL}/vault`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
      },
      body: JSON.stringify({
        title: finalTitle,
        data: finalData,
        nonce: btoa(String.fromCharCode(...nonce)),
      }),
    });

    document.querySelector('#modal-container')!.innerHTML = '';
    await fetchAndDecryptItems();
  } catch (err) {
    alert('Erro ao salvar item.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Salvar';
  }
}

async function encryptWithNonce(text: string, key: CryptoKey, nonce: Uint8Array): Promise<string> {
  const encoded = new TextEncoder().encode(text);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encoded
  );
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function deleteItem(id: string) {
  if (!confirm('Deseja realmente excluir este item?')) return;

  await fetch(`${API_URL}/vault/${id}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${state.token}` },
  });
  await fetchAndDecryptItems();
}

function logout() {
  state.token = null;
  state.keys = null;
  state.user = null;
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  renderLogin();
}

init();
