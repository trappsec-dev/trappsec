
const API_BASE = '';

const getHeaders = () => {
    const headers = {
        'Content-Type': 'application/json'
    };
    const userId = localStorage.getItem('trappsec_user_id');
    if (userId) {
        headers['x-user-id'] = userId;
    }
    return headers;
};

const handleResponse = async (response) => {
    if (!response.ok) {
        if (response.status === 401) {
            localStorage.removeItem('trappsec_user_id');
            window.location.reload();
            throw new Error('Session expired');
        }
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Request failed with status ${response.status}`);
    }
    return response.json();
};

export const api = {
    async register(email) {
        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({
                email,
                role: 'user',
                credits: 0,
                is_admin: false
            })
        });
        return handleResponse(response);
    },

    async getProfile() {
        const response = await fetch(`${API_BASE}/api/v2/profile`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    },


    async updateProfile(data) {
        const payload = {};
        if (data.name) payload.name = data.name;

        const response = await fetch(`${API_BASE}/api/v2/profile`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(payload)
        });
        return handleResponse(response);
    },

    /**
     * Get list of all orders
     */
    async getOrders() {
        const response = await fetch(`${API_BASE}/api/v2/orders`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    },

    /**
     * INTERNAL DEBUG: Get system deployment config
     * @deprecated Should be removed in prod
     */
    async getSystemConfig() {
        const response = await fetch(`${API_BASE}/deployment/config`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    },

    /**
     * INTERNAL DEBUG: Get system performance metrics
     * @deprecated Should be removed in prod
     */
    async getSystemMetrics() {
        const response = await fetch(`${API_BASE}/deployment/metrics`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    }
};
