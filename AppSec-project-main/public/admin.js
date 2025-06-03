document.addEventListener('DOMContentLoaded', () => {
  /* ---------- زر تسجيل الخروج ---------- */
  
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      try {
        //await fetch('/logout');
        window.location.href = '/logout';
      } catch (err) {
        console.error('Logout failed:', err);
      }
        fetch('/logout', { credentials: 'include' })
      .finally(() => location.href = '/login');
    });
  }

  /* ---------- Toast (رسالة عابرة) ---------- */
  const toast = document.getElementById('toast');
  function showToast(msg) {
    toast.textContent = msg;
    toast.style.display = 'block';
    setTimeout(() => toast.style.display = 'none', 3000);
  }

  /* ---------- صندوق التأكيد ---------- */
  const overlay    = document.getElementById('overlay');
  const yesBtn     = document.getElementById('confirmYes');
  const noBtn      = document.getElementById('confirmNo');
  const confirmMsg = document.getElementById('confirmMsg');

  function confirmDelete(id, name) {
    confirmMsg.textContent = `Delete user "${name}"?`;
    overlay.style.display = 'flex';

    yesBtn.onclick = () => performDelete(id);
    noBtn.onclick  = () => overlay.style.display = 'none';
  }

  async function performDelete(id) {
    overlay.style.display = 'none';
    try {
      const res = await fetch(`/admin/users/${id}`, { method: 'DELETE' });
      if (res.ok) {
        document.getElementById(`u-${id}`).remove();
        showToast('User deleted ✅');
      } else {
        showToast('Failed to delete user ❌');
      }
    } catch {
      showToast('Error while deleting user ❌');
    }
  }

  /* ---------- جلب المستخدمين ---------- */
  async function fetchUsers() {
    try {
      const res = await fetch('/admin/users');
      const users = await res.json();
      const tbody = document.getElementById('user-table-body');
      tbody.innerHTML = '';

      users.forEach(u => {
        const tr = document.createElement('tr');
        tr.id = `u-${u._id}`;
        tr.innerHTML = `
          <td>${u.name}</td>
          <td>${u.email}</td>
          <td>${u.role || 'user'}</td>
          <td><button class="delete-btn" data-id="${u._id}" data-name="${u.name}">Delete</button></td>
        `;
        tbody.appendChild(tr);
      });

      // ربط الأحداث بأزرار الحذف بعد توليدهم
      document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const id = btn.getAttribute('data-id');
          const name = btn.getAttribute('data-name');
          confirmDelete(id, name);
        });
      });

    } catch (err) {
      showToast('❌ Failed to load users');
      console.error('Fetch users error:', err);
    }
  }

  // نداء لجلب المستخدمين عند التحميل
  fetchUsers();
});
