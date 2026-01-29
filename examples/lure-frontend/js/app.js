import { api } from './api.js';

const app = {
    containers: {
        auth: document.getElementById('auth-container'),
        dashboard: document.getElementById('dashboard-container')
    },
    forms: {
        login: document.getElementById('login-form'),
        register: document.getElementById('register-form')
    },
    inputs: {
        loginUsername: document.getElementById('login-username'),
        registerEmail: document.getElementById('register-email')
    },
    buttons: {
        logout: document.getElementById('logout-btn'),
        refreshOrders: document.getElementById('refresh-orders-btn'),
        updateProfile: document.getElementById('update-profile-btn')
    },
    display: {
        headerUsername: document.getElementById('header-username'),
        profileName: document.getElementById('profile-name'),
        profileRole: document.getElementById('profile-admin'), // Keeping ID as profile-admin for compatibility with structure, but displaying derived text
        ordersTableBody: document.querySelector('#orders-table tbody')
    }
};

const state = {
    isAuthenticated: () => !!localStorage.getItem('trappsec_user_id'),
    currentUser: () => localStorage.getItem('trappsec_user_id')
};

const showToast = (message, type = 'success') => {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="icon">${type === 'success' ? '✓' : '!'}</span>
        <span>${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
};

const ui = {
    init() {
        if (state.isAuthenticated()) {
            this.showDashboard();
        } else {
            this.showAuth();
        }
        this.bindEvents();
    },

    bindEvents() {
        document.getElementById('switch-to-register').addEventListener('click', (e) => {
            e.preventDefault();
            app.forms.login.classList.remove('active');
            setTimeout(() => {
                app.forms.login.style.display = 'none';
                app.forms.register.style.display = 'block';
                setTimeout(() => app.forms.register.classList.add('active'), 10);
            }, 300);
        });

        document.getElementById('switch-to-login').addEventListener('click', (e) => {
            e.preventDefault();
            app.forms.register.classList.remove('active');
            setTimeout(() => {
                app.forms.register.style.display = 'none';
                app.forms.login.style.display = 'block';
                setTimeout(() => app.forms.login.classList.add('active'), 10);
            }, 300);
        });

        app.forms.login.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = app.inputs.loginUsername.value.trim();
            if (username) {
                localStorage.setItem('trappsec_user_id', username);
                this.showDashboard();
                showToast(`Welcome back, ${username}!`);
            }
        });

        app.forms.register.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = app.inputs.registerEmail.value.trim();
            try {
                const result = await api.register(email);
                showToast(`Registration successful! Check ${result.email}`);
                document.getElementById('switch-to-login').click();
                app.inputs.loginUsername.value = email.split('@')[0];
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        app.buttons.logout.addEventListener('click', () => {
            localStorage.removeItem('trappsec_user_id');
            this.showAuth();
        });
        // Dashboard Actions
        app.buttons.refreshOrders.addEventListener('click', () => this.loadOrders());

        app.buttons.updateProfile.addEventListener('click', async () => {
            try {
                // Get the edited username from the input
                const username = app.display.profileName.value.trim() || state.currentUser();
                await api.updateProfile({ name: username });

                // Update stored identity and UI
                localStorage.setItem('trappsec_user_id', username);
                app.display.headerUsername.textContent = username;

                showToast('Profile updated successfully');
                this.loadProfile();
            } catch (err) {
                showToast('Failed to update profile', 'error');
            }
        });
    },

    showAuth() {
        app.containers.dashboard.classList.remove('active');
        app.containers.auth.classList.add('active');
        app.forms.login.classList.add('active');
        app.forms.register.classList.remove('active');
        app.forms.register.style.display = 'none';
    },

    showDashboard() {
        app.containers.auth.classList.remove('active');
        app.containers.dashboard.classList.add('active');
        app.display.headerUsername.textContent = state.currentUser();

        // Load Data
        this.loadProfile();
        this.loadOrders();
    },

    async loadProfile() {
        try {
            const profile = await api.getProfile();
            app.display.profileName.value = profile.name || state.currentUser(); // Use .value for input
            app.display.profileRole.textContent = profile.is_admin ? 'Admin' : 'User';
        } catch (err) {
            console.error('Profile load failed', err);
        }
    },

    async loadOrders() {
        try {
            const data = await api.getOrders();
            const orders = data.orders || [];
            app.display.ordersTableBody.innerHTML = orders.map(order => `
                <tr>
                    <td>${order.id}</td>
                    <td>${order.item}</td>
                    <td><span class="badge" style="background: rgba(255,255,255,0.1); color: inherit">$${order.amount}</span></td>
                </tr>
            `).join('');
        } catch (err) {
            console.error('Orders load failed', err);
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ui.init();
});
