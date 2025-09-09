document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const usuario = document.getElementById('usuario').value;
        const contraseña = document.getElementById('contraseña').value;
        const btnLogin = document.getElementById('btnLogin');
        const errorMessage = document.getElementById('errorMessage');

        btnLogin.disabled = true;
        btnLogin.textContent = 'Ingresando...';
        errorMessage.style.display = 'none';

        localStorage.clear();
        sessionStorage.clear();
        authToken = null;

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ usuario, contraseña })
            });

            const data = await response.json();
            
            const userInfo = document.getElementById('userInfo');
            if (userInfo) {
                userInfo.textContent = `Bienvenido, ${usuario}`;
            }
            if (response.ok) {
                localStorage.setItem('authToken', data.token);
                showDashboard();
                if(data.user.rol != "funeraria")
                    loadInhumaciones();

                const menuResponse = await fetch('/api/menu', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${data.token}` 
                    }
                });
                const buttonsResponse = await fetch('/api/user-buttons', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${data.token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (buttonsResponse.ok) {
                    const buttonsData = await buttonsResponse.json();
                    generateButtons(buttonsData);
                }
                if (!menuResponse.ok) {
                    const errorText = await menuResponse.text();
                    console.error('Error al obtener menú:', menuResponse.status, errorText);
                    throw new Error(`Error ${menuResponse.status}: ${errorText}`);
                }

                const menuItems = await menuResponse.json();

                // Generar menú dinámico
                const sidebar = document.getElementById('sidebar');
                if (!sidebar) {
                    console.error('Elemento sidebar no encontrado');
                    return;
                }

                sidebar.innerHTML = `<div class="sidebar-header"><h2>MENU PRINCIPAL</h2></div>`;

                if(data.user.rol == "administrador"){
                    const menuAdmin = await fetch('/api/menuadmin', {
                        method: 'GET',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${data.token}` 
                        }
                    });

                    if (menuAdmin.ok) {
                        const htmlContent = await menuAdmin.text();
                        const admin = document.getElementById('admin');
                        admin.innerHTML = htmlContent;
                        const btCrear = document.getElementById('crear');
                        if(btCrear){
                            btCrear.addEventListener('click', crearUsuario);
                        }
                    } else {
                        console.error('Error al cargar el menú admin:', menuAdmin.status);
                    }
                }

                // Verificar que menuItems sea un array
                if (Array.isArray(menuItems)) {
                    menuItems.forEach(item => {                            
                        const div = document.createElement('div');
                        if(item.clase == "active"){
                            div.classList.add('menu-item', 'active');
                            showSection(item.section);
                        }
                        else{
                            div.classList.add(item.clase); 
                        }
                        div.dataset.section = item.section;
                        div.textContent = item.label;
                            
                        div.addEventListener('click', () => {
                            if (item.section) {
                                showSection(item.section);
                            }
                        });
                            
                        sidebar.appendChild(div);
                    });
                }
                else {
                    console.error('menuItems no es un array:', menuItems);
                }
            } 
            else {
                showError(data.error || 'Error de autenticación');
            }


        } 
        catch (error) {
            console.error('Error completo:', error);
            showError('Error de conexión. Intente nuevamente.');
        } 
        finally {
            btnLogin.disabled = false;
            btnLogin.textContent = 'Ingresar';
        }

        function showError(message) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
        }

        function generateButtons(configs) {
            const buttonsContainer = document.getElementById('buttons');
            let authToken = localStorage.getItem('authToken');
            // Limpiar contenedor
            buttonsContainer.innerHTML = '';
            
            configs.forEach(config => {
                const button = document.createElement('button');
                button.type = 'button';
                button.id = config.id;
                button.className = config.class;
                button.textContent = config.text;
                
                // Agregar event listener
                button.addEventListener('click', async () => {
                    const formData = getFormDataSafe(config.action);
                    try {
                        const response = await fetch(config.path, {
                            method: 'POST',
                            headers: {
                                'Authorization': `Bearer ${authToken}`
                            },
                            body: formData
                        });
                        if (response.ok) {
                            document.getElementById('inhumacionForm').reset();
                            if (config.action=="generarLicencia"){
                                loadInhumaciones();
                            }
                            alert('Inhumación registrada exitosamente');
                        } else {
                            alert('Error al registrar inhumación');
                        }
                    } catch (error) {
                        console.error('❌ Error de conexión:', error);
                        alert('Error de conexión al servidor');
                    }
                });
                
                buttonsContainer.appendChild(button);
            });
            const button2 = document.createElement('button');
            button2.type = 'button';
            button2.id = 'cargaArchivo';
            button2.className = 'btn-agregar';
            button2.textContent = 'Cargar Archivos';
            button2.addEventListener('click', showUploadModal);
            buttonsContainer.appendChild(button2)
        }

        // Función para mostrar modal de carga de archivos
        function showUploadModal() {
            document.getElementById('cargarModal').style.display = 'block';
        }

        function getFormDataSafe(llamadoBoton) {
            const campos = {
                idInhuma: 'idInhuma',
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

            const formData = new FormData();
            const camposFaltantes = [];

            for (const [key, id] of Object.entries(campos)) {
                if(id == 'requiereTraslado'){
                    if(document.getElementById('traslado1').checked == true){
                        formData.append(key,'Si');
                    }
                    else{
                        formData.append(key,'No');
                    }
                }
                else if(id == 'solicitarLicencia'){
                    formData.append(key,"Pendiente");
                }
                else if(id == 'generarLicencia'){
                    formData.append(key,"Aprobado");
                }
                else {
                    const elemento = document.getElementById(id);
                    
                    if (elemento && elemento.value !== undefined) {
                        formData.append(key,elemento.value);
                    } else {
                        console.error(`❌ Campo faltante: ${id}`);
                        camposFaltantes.push(id);
                        formData.append(key,''); // Valor por defecto
                    }
                }
            }

            const archivos = document.getElementById('archivos').files;
            Array.from(archivos).forEach((file, index) => {
            formData.append("archivos", file); 
            });

            return formData;
        }

        async function loadInhumaciones() {
            let authToken = localStorage.getItem('authToken');
            const tokenParts = authToken ? authToken.split('.') : [];
            if (tokenParts.length !== 3) {
                const cleanToken = data.token.trim();
                localStorage.setItem('authToken', cleanToken);
                authToken = cleanToken;
            }
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



        async function displayInhumaciones(inhumaciones) {
        const container = document.getElementById('inhumacionesList');
        
        if (inhumaciones.length === 0) {
            container.innerHTML = '<p>No hay registros de inhumaciones pendientes</p>';
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
            <tbody id="inhumaciones-tbody">
            `;

        const html = inhumaciones.map(inhumacion => `
            <tr>
                <td>${escapeHtml(inhumacion.nombreSolicitante)}</td>
                <td id="archivos-${inhumacion.id}">Cargando...</td>
                <td>${escapeHtml(inhumacion.certificadoDefuncion)}</td>
                <td>${new Date(inhumacion.fechaActualizacion).toLocaleDateString()}</td>
                <td>${escapeHtml(inhumacion.requiereTraslado)}</td>
                <td>${escapeHtml(inhumacion.ciudadOrigen || 'N/A')}</td>
                <td>${escapeHtml(inhumacion.ciudadDestino || 'N/A')}</td>
                <td>
                    <a href="#" class="link-btn action-btn" data-action="autorizar" data-id="${inhumacion.id}">Autorizar</a>
                    <a href="#" class="link-btn action-btn" data-action="rechazar" data-id="${inhumacion.id}">Rechazar</a>
                </td>
            </tr>
        `).join('');

        const footer = `</tbody></table>`;
        container.innerHTML = header + html + footer;

        const tableBody = document.getElementById('inhumaciones-tbody');
        if (tableBody) {
            tableBody.addEventListener('click', handleActionClick);
        } else {
            console.error('Elemento tbody con ID "inhumaciones-tbody" no encontrado');
        }

        // 🔹 renderInhumaciones embebida
        async function renderInhumaciones(id) {
            let authToken = localStorage.getItem('authToken');
            try {
                const res = await fetch(`/api/inhumaciones/${id}/archivos`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                const archivos = await res.json();

                const cell = document.getElementById(`archivos-${id}`);
                if (!archivos || archivos.length === 0) {
                    cell.innerHTML = '📂 Sin archivos';
                    return;
                }

                // Muestra un ícono por cada archivo
                cell.innerHTML = archivos.map((archivo, index) => `
                    <a href="${archivo.ruta}" target="_blank" title="${escapeHtml(archivo.nombreOriginal)}">
                        📄${index + 1}
                    </a>
                `).join(' ');
            } catch (err) {
                console.error('Error obteniendo archivos:', err);
                document.getElementById(`archivos-${id}`).innerHTML = '⚠️ Error';
            }
        }

        // 🔹 Ejecutamos renderInhumaciones por cada fila
        inhumaciones.forEach(inhumacion => {
            renderInhumaciones(inhumacion.id);
        });
    }

        function handleActionClick(event) {
            // Verificar si el click fue en un botón de acción
            if (event.target.classList.contains('action-btn')) {
                event.preventDefault();
                
                const action = event.target.dataset.action;
                const id = event.target.dataset.id;
                
                switch(action) {
                    case 'autorizar':
                        autorizarLicencia(parseInt(id));
                        break;
                    case 'rechazar':
                        showRejectModal(parseInt(id));
                        break;
                    case 'Visualizar':
                        abrirPDF(parseInt(id));
                        break;
                    case 'Descargar':
                        descargarPDF(parseInt(id));
                        break;
                    case 'Tramitar':
                        cargarDatosLicencia(parseInt(id));
                        break;
                    default:
                        console.warn('Acción no reconocida:', action);
                }
            }
        }
        async function cargarDatosLicencia(id){
            let authToken = localStorage.getItem('authToken');
            try {
                const response = await fetch(`/api/${id}/inhumaciones`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });

                if (response.ok) {
                    const inhumaciones = await response.json();

                    const fecha = new Date(inhumaciones.fechaDefuncion);
                    // Ajustar a formato YYYY-MM-DD
                    const fechaISO = fecha.toISOString().split("T")[0];
                    document.getElementById('idInhuma').value = inhumaciones.id;
                    document.getElementById('numeroDocumento').value = inhumaciones.numeroDocumento;
                    document.getElementById('nombres').value = inhumaciones.nombres;
                    document.getElementById('primerApellido').value = inhumaciones.primerApellido;
                    document.getElementById('segundoApellido').value = inhumaciones.segundoApellido;
                    document.getElementById('tipoDocumento').value = inhumaciones.tipoDocumento;
                    document.getElementById('nombreSolicitante').value = inhumaciones.nombreSolicitante;
                    document.getElementById('sexo').value = inhumaciones.sexo;
                    document.getElementById('tipoMuerte').value = inhumaciones.tipoMuerte;
                    document.getElementById('fechaDefuncion').value = fechaISO;
                    document.getElementById('certificadoDefuncion').value = inhumaciones.certificadoDefuncion;
                    document.getElementById('edad').value = inhumaciones.edad;
                    document.getElementById('tipoEdad').value = inhumaciones.tipoEdad;
                    document.getElementById('ciudadOrigen').value = inhumaciones.ciudadOrigen;
                    document.getElementById('ciudadDestino').value = inhumaciones.ciudadDestino;
                    if(inhumaciones.requiereTraslado === 'Si')
                        document.getElementById('traslado1').checked = true;
                    else
                        document.getElementById('traslado2').checked = true;

                    showSection("generar");
                }
            } catch (error) {
                console.error('Inhumacion no encontrada');
            }
        }

        function abrirPDF(licenciaId, modo = 'view') {
            const url = `/api/licencia/${licenciaId}/${modo}`;
            
            // Configuración de la nueva ventana
            const windowFeatures = 'width=900,height=700,scrollbars=yes,resizable=yes,status=yes,menubar=yes,toolbar=yes';
            
            // Abrir nueva ventana
            const nuevaVentana = window.open(url, `PDF_Licencia_${licenciaId}`, windowFeatures);
            
            // Verificar si se pudo abrir (bloqueador de pop-ups)
            if (!nuevaVentana || nuevaVentana.closed || typeof nuevaVentana.closed == 'undefined') {
                alert('El navegador bloqueó la ventana emergente. Por favor, permite las ventanas emergentes para este sitio.');
                return false;
            }
            
            // Opcional: Enfocar la nueva ventana
            nuevaVentana.focus();
            
            return true;
        }

        function descargarPDF(licenciaId) {
            const url = `/api/licencia/${licenciaId}/pdf`;
            
            // Crear elemento de descarga temporal
            const link = document.createElement('a');
            link.href = url;
            link.download = `licencia-${licenciaId}.pdf`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        async function autorizarLicencia(id) {
            let authToken = localStorage.getItem('authToken');
            try {
                const response = await fetch(`/api/inhumaciones/autorizar/${id}`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });

                if (!response.ok) {
                    document.getElementById('inhumacionesList').innerHTML = '<p>Error al autorizar licencia</p>';
                    return;
                }

                const result = await response.json();
                alert(result.message);

                // Refrescar la lista
                await loadInhumaciones();

            } catch (error) {
                console.error('Error en autorizarLicencia:', error);
                document.getElementById('inhumacionesList').innerHTML = '<p>Error de conexión</p>';
            }
                        
        }

        function showRejectModal(id) {
            document.getElementById('rejectModal').style.display = 'block';
            localStorage.setItem('idReject', id);
        }

        // Función de utilidad para escapar HTML (seguridad)
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        window.loadInhumaciones = loadInhumaciones;
        window.escapeHtml = escapeHtml;
        window.handleActionClick = handleActionClick;
    });
});

