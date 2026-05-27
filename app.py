import os
import time
import joblib
import pandas as pd
import plotly.express as px
import streamlit as st

# =====================================================
# CONFIGURACIÓN GENERAL
# =====================================================

st.set_page_config(
    page_title="Sistema de Detección de Ciberataques",
    layout="wide"
)

# =====================================================
# ESTILO VISUAL
# =====================================================

st.markdown(
    """
    <style>
    .main {
        background-color: #f7f9fc;
    }

    .titulo-principal {
        font-size: 34px;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0px;
    }

    .subtitulo {
        font-size: 18px;
        color: #4b5563;
        margin-bottom: 30px;
    }

    .card {
        background-color: white;
        padding: 22px;
        border-radius: 14px;
        box-shadow: 0px 2px 10px rgba(0,0,0,0.08);
        text-align: center;
    }

    .metric-title {
        color: #6b7280;
        font-size: 14px;
        margin-bottom: 8px;
    }

    .metric-value {
        color: #111827;
        font-size: 32px;
        font-weight: 700;
    }

    .section-title {
        font-size: 24px;
        font-weight: 650;
        color: #1f2937;
        margin-top: 35px;
        margin-bottom: 15px;
    }

    .info-box {
        background-color: white;
        padding: 18px;
        border-left: 5px solid #2563eb;
        border-radius: 10px;
        color: #374151;
        box-shadow: 0px 2px 8px rgba(0,0,0,0.06);
    }

    .sidebar-card {
        background-color: #ffffff;
        padding: 16px;
        border-radius: 12px;
        margin-bottom: 14px;
        box-shadow: 0px 2px 8px rgba(0,0,0,0.08);
        color: #1f2937;
    }

    .sidebar-title {
        font-size: 18px;
        font-weight: 700;
        color: #111827;
        margin-bottom: 8px;
    }

    .sidebar-text {
        font-size: 14px;
        color: #4b5563;
        line-height: 1.5;
    }

    .alert-critical {
        background-color: #fee2e2;
        border-left: 6px solid #dc2626;
        padding: 18px;
        border-radius: 12px;
        color: #7f1d1d;
        font-weight: 500;
        margin-bottom: 20px;
    }

    .alert-medium {
        background-color: #fef3c7;
        border-left: 6px solid #d97706;
        padding: 18px;
        border-radius: 12px;
        color: #78350f;
        font-weight: 500;
        margin-bottom: 20px;
    }

    .alert-normal {
        background-color: #dcfce7;
        border-left: 6px solid #16a34a;
        padding: 18px;
        border-radius: 12px;
        color: #14532d;
        font-weight: 500;
        margin-bottom: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =====================================================
# CARGA DEL MODELO
# =====================================================

modelo = joblib.load("modelo_final_hgb.pkl")
scaler = joblib.load("scaler.pkl")

# =====================================================
# FUNCIONES
# =====================================================

def clasificar_prediccion(valor):
    valor_str = str(valor).lower()

    if valor_str in ["benign", "benigno", "0"]:
        return "Benign"

    return "DDoS attacks-LOIC-HTTP"


def preparar_datos(df):
    try:
        columnas_modelo = scaler.feature_names_in_
        df_modelo = df[columnas_modelo]
    except Exception:
        df_modelo = df.copy()

    X = scaler.transform(df_modelo)
    predicciones = modelo.predict(X)

    df_resultado = df.copy()
    df_resultado["Predicción"] = predicciones
    df_resultado["Predicción"] = df_resultado["Predicción"].apply(clasificar_prediccion)

    return df_resultado


def mostrar_alerta(porcentaje_malicioso):
    if porcentaje_malicioso >= 30:
        st.markdown(
            f"""
            <div class="alert-critical">
                <b>ALERTA CRÍTICA</b><br>
                Se ha detectado un volumen elevado de tráfico malicioso.
                Porcentaje actual de tráfico malicioso: <b>{porcentaje_malicioso}%</b>.
            </div>
            """,
            unsafe_allow_html=True
        )

    elif porcentaje_malicioso >= 10:
        st.markdown(
            f"""
            <div class="alert-medium">
                <b>ALERTA MEDIA</b><br>
                Se ha detectado un incremento relevante de tráfico malicioso.
                Porcentaje actual de tráfico malicioso: <b>{porcentaje_malicioso}%</b>.
            </div>
            """,
            unsafe_allow_html=True
        )

    else:
        st.markdown(
            f"""
            <div class="alert-normal">
                <b>ESTADO NORMAL</b><br>
                El tráfico analizado no presenta actividad maliciosa significativa.
                Porcentaje actual de tráfico malicioso: <b>{porcentaje_malicioso}%</b>.
            </div>
            """,
            unsafe_allow_html=True
        )


def mostrar_dashboard(df_resultado, mostrar_descarga=True, key_prefix="normal"):
    total = len(df_resultado)
    conteo = df_resultado["Predicción"].value_counts()

    benignos = conteo.get("Benign", 0)
    ataques = total - benignos
    porcentaje_malicioso = round((ataques / total) * 100, 2) if total > 0 else 0

    mostrar_alerta(porcentaje_malicioso)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="card">
                <div class="metric-title">Registros analizados</div>
                <div class="metric-value">{total}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div class="card">
                <div class="metric-title">Ataques detectados</div>
                <div class="metric-value">{ataques}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            f"""
            <div class="card">
                <div class="metric-title">Tráfico benigno</div>
                <div class="metric-value">{benignos}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="card">
                <div class="metric-title">Porcentaje malicioso</div>
                <div class="metric-value">{porcentaje_malicioso}%</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown('<div class="section-title">Distribución de predicciones</div>', unsafe_allow_html=True)

    df_conteo = conteo.reset_index()
    df_conteo.columns = ["Clase", "Cantidad"]

    col_graf1, col_graf2 = st.columns(2)

    with col_graf1:
        fig_bar = px.bar(
            df_conteo,
            x="Clase",
            y="Cantidad",
            text="Cantidad",
            title="Cantidad de registros por clase",
            color="Clase"
        )

        fig_bar.update_traces(textposition="outside")
        fig_bar.update_layout(
            showlegend=False,
            height=420,
            margin=dict(l=20, r=20, t=60, b=20)
        )

        st.plotly_chart(
            fig_bar,
            use_container_width=True,
            key=f"{key_prefix}_bar_{total}"
        )

    with col_graf2:
        fig_pie = px.pie(
            df_conteo,
            names="Clase",
            values="Cantidad",
            title="Porcentaje de tráfico detectado",
            hole=0.35
        )

        fig_pie.update_layout(
            height=420,
            margin=dict(l=20, r=20, t=60, b=20)
        )

        st.plotly_chart(
            fig_pie,
            use_container_width=True,
            key=f"{key_prefix}_pie_{total}"
        )

    st.markdown('<div class="section-title">Últimos registros analizados</div>', unsafe_allow_html=True)
    st.dataframe(df_resultado.tail(100), use_container_width=True)

    if mostrar_descarga:
        csv = df_resultado.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Descargar resultados",
            data=csv,
            file_name="predicciones.csv",
            mime="text/csv",
            key=f"{key_prefix}_download_{total}"
        )


# =====================================================
# CABECERA
# =====================================================

st.markdown(
    """
    <div class="titulo-principal">Sistema Inteligente de Detección de Ciberataques</div>
    <div class="subtitulo">
    Dashboard para el análisis de tráfico de red mediante modelos de Machine Learning
    </div>
    """,
    unsafe_allow_html=True
)

# =====================================================
# PANEL LATERAL
# =====================================================

st.sidebar.header("Configuración del sistema")

st.sidebar.markdown("**Modelo activo**")
st.sidebar.info("HistGradientBoostingClassifier")

st.sidebar.markdown("**Tipo de análisis**")
st.sidebar.write("Detección de tráfico benigno y ataques DDoS.")

st.sidebar.markdown("---")

st.sidebar.markdown("**Umbrales de alerta**")

st.sidebar.write("Normal: < 10% tráfico malicioso")
st.sidebar.write("Alerta media: 10% - 30%")
st.sidebar.write("Alerta crítica: > 30%")

st.sidebar.markdown("---")

st.sidebar.markdown("**Funcionamiento**")
st.sidebar.write("1. Cargar CSV completo")
st.sidebar.write("2. Ejecutar monitorización")
st.sidebar.write("3. Analizar predicciones")

# =====================================================
# PESTAÑAS
# =====================================================

tab1, tab2 = st.tabs(["Análisis por CSV", "Monitorización en tiempo real"])

# =====================================================
# TAB 1 - ANÁLISIS POR CSV
# =====================================================

with tab1:
    st.markdown('<div class="section-title">Análisis de archivo CSV</div>', unsafe_allow_html=True)

    archivo = st.file_uploader(
        "Seleccionar archivo CSV",
        type=["csv"]
    )

    if archivo is not None:
        df = pd.read_csv(archivo)

        st.markdown('<div class="section-title">Vista previa del dataset</div>', unsafe_allow_html=True)
        st.dataframe(df.head(), use_container_width=True)

        df_resultado = preparar_datos(df)
        mostrar_dashboard(df_resultado, mostrar_descarga=True, key_prefix="csv")

    else:
        st.info("Sube un archivo CSV para comenzar el análisis.")

# =====================================================
# TAB 2 - MONITORIZACIÓN EN TIEMPO REAL
# =====================================================

with tab2:
    st.markdown('<div class="section-title">Monitorización en tiempo real</div>', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="info-box">
        Esta sección simula la llegada progresiva de tráfico de red.
        El sistema lee registros de un archivo CSV y actualiza las predicciones dinámicamente.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")

    archivo_live = st.text_input(
        "Archivo de monitorización",
        value="trafico_live.csv"
    )

    num_registros = st.slider(
        "Número de registros a procesar por actualización",
        min_value=10,
        max_value=200,
        value=50,
        step=10
    )

    tiempo_espera = st.slider(
        "Intervalo de actualización en segundos",
        min_value=1,
        max_value=10,
        value=2,
        step=1
    )

    iniciar = st.button("Iniciar monitorización")

    if iniciar:

        if not os.path.exists(archivo_live):
            st.error(f"No se ha encontrado el archivo {archivo_live}.")
        else:
            df_live = pd.read_csv(archivo_live)

            if len(df_live) == 0:
                st.error("El archivo de monitorización está vacío.")
            else:
                placeholder = st.empty()
                df_acumulado = pd.DataFrame()

                for i in range(0, len(df_live), num_registros):
                    bloque = df_live.iloc[i:i + num_registros]
                    df_acumulado = pd.concat([df_acumulado, bloque], ignore_index=True)

                    df_resultado_live = preparar_datos(df_acumulado)

                    with placeholder.container():
                        st.markdown(
                            f"""
                            <div class="info-box">
                            Registros procesados hasta el momento: <b>{len(df_resultado_live)}</b>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                        mostrar_dashboard(
                            df_resultado_live,
                            mostrar_descarga=False,
                            key_prefix=f"live_{len(df_resultado_live)}"
                        )

                    time.sleep(tiempo_espera)

                st.success("Monitorización finalizada.")