const fileInput = document.getElementById('fileInput');
        const selectedFiles = document.getElementById('selectedFiles');
        const uploadForm = document.getElementById('uploadForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageDiv = document.getElementById('message');
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');

        // Mostrar archivos seleccionados
        fileInput.addEventListener('change', function() {
            const files = Array.from(this.files);
            if (files.length > 0) {
                let html = '<h4>Archivos seleccionados:</h4><ul>';
                files.forEach(file => {
                    const sizeInMB = (file.size / (1024 * 1024)).toFixed(2);
                    html += `<li><strong>${file.name}</strong> (${sizeInMB} MB)</li>`;
                });
                html += '</ul>';
                selectedFiles.innerHTML = html;
            } else {
                selectedFiles.innerHTML = '';
            }
        });

        // Drag and drop functionality
        const fileInputDiv = document.querySelector('.file-input');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            fileInputDiv.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            fileInputDiv.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            fileInputDiv.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            fileInputDiv.style.borderColor = '#007bff';
            fileInputDiv.style.backgroundColor = '#f0f8ff';
        }

        function unhighlight(e) {
            fileInputDiv.style.borderColor = '#ddd';
            fileInputDiv.style.backgroundColor = '#fafafa';
        }

        fileInputDiv.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            
            // Trigger change event
            const event = new Event('change', { bubbles: true });
            fileInput.dispatchEvent(event);
        }

        // Handle form submission
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData1 = new FormData1();
            const files = fileInput.files;
            
            if (files.length === 0) {
                showMessage('Por favor selecciona al menos un archivo', 'error');
                return;
            }
            
            // Validar número de archivos
            if (files.length > 3) {
                showMessage('Máximo 3 archivos', 'error');
                return;
            }
            
            // Validar tamaño de archivos
            for (let file of files) {
                if (file.size > 5 * 1024 * 1024) { // 5MB
                    showMessage(`El archivo ${file.name} excede el tamaño máximo de 5MB`, 'error');
                    return;
                }
            }
            
            for (let file of files) {
                formData1.append('documents', file);
            }
            
            // Show progress
            progressContainer.style.display = 'block';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Subiendo...';
            
            try {
                const xhr = new XMLHttpRequest();
                
                // Track upload progress
                xhr.upload.addEventListener('progress', (e) => {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        progressBar.style.width = percentComplete + '%';
                        progressText.textContent = Math.round(percentComplete) + '%';
                    }
                });
                
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        const result = JSON.parse(xhr.responseText);
                        showMessage('Archivos subidos correctamente', 'success');
                        loadFileList();
                        uploadForm.reset();
                        selectedFiles.innerHTML = '';
                    } else {
                        const error = JSON.parse(xhr.responseText);
                        showMessage(error.error || 'Error al subir archivos', 'error');
                    }
                    resetUploadState();
                };
                
                xhr.onerror = function() {
                    showMessage('Error de conexión al subir archivos', 'error');
                    resetUploadState();
                };
                
                xhr.open('POST', '/upload');
                xhr.send(formData1);
                
            } catch (error) {
                showMessage('Error inesperado al subir archivos', 'error');
                resetUploadState();
            }
        });
        
        function resetUploadState() {
            progressContainer.style.display = 'none';
            progressBar.style.width = '0%';
            progressText.textContent = '0%';
            submitBtn.disabled = false;
            submitBtn.textContent = 'Subir Archivos';
        }
        
        function showMessage(text, type) {
            messageDiv.innerHTML = `<div class="message ${type}">${text}</div>`;
            // Auto-hide success messages after 5 seconds
            if (type === 'success') {
                setTimeout(() => {
                    messageDiv.innerHTML = '';
                }, 5000);
            }
        }
        // Variables globales
        let currentUser = JSON.parse(localStorage.getItem('currentUser') || '{}');
        let authToken = localStorage.getItem('authToken');

        function validateTokenOnLoad() {
            console.log('🔍 Validando token al cargar la página...');
            
            if (!authToken) {
                console.log('❌ No hay token guardado');
                return false;
            }
            
            if (isTokenExpired(authToken)) {
                console.log('❌ Token expirado');
                return false;
            }
            
            console.log('✅ Token válido');
            return true;
        }
        function isTokenExpired(authToken) {
            if (!authToken) return true;
            
            const decoded = parseJWT(authToken);
            if (!decoded || !decoded.exp) return true;
            
            const currentTime = Date.now() / 1000;
            return decoded.exp < currentTime;
        }
        function parseJWT(authToken) {
            try {
                const base64Url = authToken.split('.')[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
                return JSON.parse(jsonPayload);
            } catch (error) {
                console.error('Error parsing JWT:', error);
                return null;
            }
        }
        

        // Verificar si ya está autenticado
        if (validateTokenOnLoad()) {
            showDashboard();
            loadInhumaciones();
        }

        // Manejo del formulario de login
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const usuario = document.getElementById('usuario').value;
            const contraseña = document.getElementById('contraseña').value;
            const btnLogin = document.getElementById('btnLogin');
            const errorMessage = document.getElementById('errorMessage');
            
            btnLogin.disabled = true;
            btnLogin.textContent = 'Ingresando...';
            errorMessage.style.display = 'none';

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ usuario, contraseña })
                });

                const data = await response.json();

                if (response.ok) {
                    authToken = data.token;
                    currentUser = data.user;
                    localStorage.setItem('authToken', authToken);
                    localStorage.setItem('currentUser', JSON.stringify(currentUser));
                    showDashboard();
                } else {
                    showError(data.error || 'Error de autenticación');
                }
            } catch (error) {
                showError('Error de conexión. Intente nuevamente.');
            } finally {
                btnLogin.disabled = false;
                btnLogin.textContent = 'Ingresar';
            }
        });

        async function loadInhumaciones() {
            try {
                const response = await fetch('/api/inhumaciones', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });

                if (response.ok) {
                    const inhumaciones = await response.json();
                    displayInhumaciones(inhumaciones);
                } else {
                    document.getElementById('inhumacionesList').innerHTML = '<p>Error al cargar registros</p>';
                }
            } catch (error) {
                document.getElementById('inhumacionesList').innerHTML = '<p>Error de conexión</p>';
            }
        }

        function displayInhumaciones(inhumaciones) {
            const container = document.getElementById('inhumacionesList');
            
            if (inhumaciones.length === 0) {
                container.innerHTML = '<p>No hay registros de inhumaciones</p>';
                return;
            }

            const header = `<table class="table">
                <thead>
                    <tr>
                        <th>Solicitado por</th>
                        <th>Adjuntos</th>
                        <th>Numero certificado defuncion</th>
                        <th>Fecha Ultima Actualizacion </th>
                        <th>Requiere Traslado</th>
                        <th>Ciudad Origen</th>
                        <th>Ciudad Destino</th>
                        <th>Opciones</th>
                    </tr>
                </thead>
                <tbody>
                `

            const html = inhumaciones.map(inhumacion => `
                <tr>
                    <td>${inhumacion.nombreSolicitante}</td>
                    <td>📎</td>
                    <td>${inhumacion.certificadoDefuncion}</td>
                    <td>${new Date(inhumacion.fechaActualizacion).toLocaleDateString()}</td>
                    <td>${inhumacion.requiereTraslado}</td>
                    <td>${inhumacion.ciudadOrigen || 'N/A'}</td>
                    <td>${inhumacion.ciudadDestino || 'N/A'}</td>
                    <td>
                        <a href="#" class="link-btn" onclick="autorizarLicencia(${inhumacion.id})">Autorizar</a>
                        <a href="#" class="link-btn" onclick="showRejectModal(${inhumacion.id})">Rechazar</a>
                    </td>
                </tr>
            `).join('');

            const footer = `</tbody></table>`

            container.innerHTML = header + html + footer;
        }

        // Funciones auxiliares
        function showError(message) {
            const errorElement = document.getElementById('errorMessage');
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }

        function showDashboard() {
            document.getElementById('loginContainer').style.display = 'none';
            document.getElementById('sidebar').style.display = 'block';
            document.getElementById('dashboard').style.display = 'block';
            document.getElementById('userInfo').textContent = `Bienvenido, ${currentUser.username}`;
            //loadInhumaciones();
        }

        function showSection(sectionId) {
            // Ocultar todas las secciones
            const sections = document.querySelectorAll('.section');
            sections.forEach(section => section.classList.add('hidden'));

            // Mostrar la sección seleccionada
            document.getElementById(sectionId).classList.remove('hidden');

            // Actualizar el menú activo
            const menuItems = document.querySelectorAll('.menu-item');
            menuItems.forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');

            //actualizar Registros
            loadInhumaciones();
        }

        function getFormDataSafe(llamadoBoton) {
            const campos = {
                numeroDocumento: 'numeroDocumento',
                nombres: 'nombres',
                primerApellido: 'primerApellido',
                segundoApellido: 'segundoApellido',
                tipoDocumento: 'tipoDocumento',
                nombreSolicitante: 'nombreSolicitante',
                sexo: 'sexo',
                tipoMuerte: 'tipoMuerte',
                fechaDefuncion: 'fechaDefuncion',
                certificadoDefuncion: 'certificadoDefuncion',
                edad: 'edad',
                tipoEdad: 'tipoEdad',
                ciudadOrigen: 'ciudadOrigen',
                ciudadDestino: 'ciudadDestino',
                requiereTraslado: 'requiereTraslado',
                autorizado: llamadoBoton
            };

            const formData = {};
            const camposFaltantes = [];

            for (const [key, id] of Object.entries(campos)) {
                if(id == 'requiereTraslado'){
                    if(document.getElementById('traslado1').checked == true){
                        formData[key] = 'Si';
                    }
                    else{
                        formData[key] = 'No';
                    }
                }
                else if(id == 'solicitarLicencia'){
                    formData[key] = "Pendiente";
                }
                else if(id == 'generarLicencia'){
                    formData[key] = "Aprobado";
                    console.log(formData[key]);
                }
                else {
                    const elemento = document.getElementById(id);
                    
                    if (elemento && elemento.value !== undefined) {
                        formData[key] = elemento.value;
                    } else {
                        console.error(`❌ Campo faltante: ${id}`);
                        camposFaltantes.push(id);
                        formData[key] = ''; // Valor por defecto
                    }
                }
            }

            return formData;
        }

        function debugAuthToken() {
            if (!authToken) {
                console.error('❌ authToken es null o undefined');
                return false;
            }
            
            if (authToken === 'null' || authToken === 'undefined') {
                console.error('❌ authToken es string "null" o "undefined"');
                return false;
            }
            
            console.log('✅ authToken parece válido');
            return true;
        }

        // Manejo del formulario de solicitar licencia
        document.getElementById('solicitarLicencia').addEventListener('click', async (e) => {
            e.preventDefault();
            const formData = getFormDataSafe('solicitarLicencia');

            if (!debugAuthToken()) {
                alert('Error: Token de autenticación no válido. Por favor, inicia sesión nuevamente.');
                return;
            }
            try {
                const response = await fetch('/api/inhumaciones', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(formData)
                });
                if (response.ok) {
                    document.getElementById('inhumacionForm').reset();
                    //loadInhumaciones();
                    alert('Inhumación registrada exitosamente');
                } else {
                    alert('Error al registrar inhumación');
                }
            } catch (error) {
                console.error('❌ Error de conexión:', error);
                alert('Error de conexión al servidor');
            }
        });

        // Manejo del formulario de generar licencia
        document.getElementById('generarLicencia').addEventListener('click', async (e) => {
            e.preventDefault();
            const formData = getFormDataSafe('generarLicencia');

            if (!debugAuthToken()) {
                alert('Error: Token de autenticación no válido. Por favor, inicia sesión nuevamente.');
                return;
            }
            try {
                const response = await fetch('/api/inhumaciones', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(formData)
                });
                if (response.ok) {
                    document.getElementById('inhumacionForm').reset();
                    //loadInhumaciones();
                    alert('Inhumación registrada exitosamente');
                } else {
                    alert('Error al registrar inhumación');
                }
            } catch (error) {
                console.error('❌ Error de conexión:', error);
                alert('Error de conexión al servidor');
            }
        });

        function generarLicencia() {
            alert('Generar licencia solo estará disponible para el usuario aprobador, los otros usuarios tendrán el botón oculto');
        }

        function showRejectModal(idInhuma) {
            document.getElementById('rejectModal').style.display = 'block';
        }

        function closeRejectModal() {
            document.getElementById('rejectModal').style.display = 'none';
            document.getElementById('rejectReason').value = '';
        }

        function confirmReject() {
            const reason = document.getElementById('rejectReason').value;
            if (reason.trim() === '') {
                alert('Por favor ingrese una razón para el rechazo');
                return;
            }
            alert('Solicitud rechazada. Razón: ' + reason);
            closeRejectModal();
        }

        // Funcionalidad para mostrar/ocultar campos según el traslado
        document.addEventListener('DOMContentLoaded', function() {
            const trasladoRadios = document.querySelectorAll('input[name="traslado"]');
            const ciudadFields = document.querySelectorAll('input[placeholder="Placeholder"]');
            
            trasladoRadios.forEach(radio => {
                radio.addEventListener('change', function() {
                    // Aquí puedes agregar lógica para mostrar/ocultar campos según el traslado
                });
            });
        });

        // Cerrar modal al hacer clic fuera
        window.onclick = function(event) {
            const modal = document.getElementById('rejectModal');
            if (event.target === modal) {
                closeRejectModal();
            }
        }
        function logout() {
            localStorage.removeItem('authToken');
            localStorage.removeItem('currentUser');
            authToken = null;
            currentUser = {};
            document.getElementById('loginContainer').style.display = 'block';
            document.getElementById('dashboard').style.display = 'none';
            document.getElementById('sidebar').style.display = 'none';
            document.getElementById('loginForm').reset();
        }
        function ocultarCampos(){
            if( document.getElementById('traslado1').checked == true){
                document.getElementById("labelOrigen").style.display = 'block'
                document.getElementById('ciudadOrigen').style.display = 'block'
                document.getElementById("labelDestino").style.display = 'block'
                document.getElementById('ciudadDestino').style.display = 'block'
            }
            else
            {
                document.getElementById("labelOrigen").style.display = 'none'
                document.getElementById('ciudadOrigen').style.display = 'none'
                document.getElementById("labelDestino").style.display = 'none'
                document.getElementById('ciudadDestino').style.display = 'none'
            }
        }
// Exponer funciones globalmente para compatibilidad con onclick inline
window.showSection = showSection;
window.logout = logout;
window.ocultarCampos = ocultarCampos;
window.openRejectModal = openRejectModal;
window.closeRejectModal = closeRejectModal;
window.confirmReject = confirmReject;
window.aprobarInhumacion = aprobarInhumacion;