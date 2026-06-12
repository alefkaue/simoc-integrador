from flask import Flask, render_template_string, request, redirect, session, url_for
from functools import wraps

app = Flask(__name__)
app.secret_key = "cymag_super_secret_key"

# ==================================================
# MOCK DATA (substituir depois pelo output do CYMAG)
# ==================================================

RISK_SCORE = 92
RISK_LEVEL = "CRÍTICO"

FINDINGS = [
    {
        "title": "SQL Injection na Aplicação Web",
        "cvss": "9.8",
        "severity": "CRÍTICO",
        "impact": "Vazamento de banco de dados e possível multa LGPD.",
        "business": [
            "Exposição de dados sensíveis",
            "Impacto reputacional",
            "Sanções regulatórias"
        ]
    },

    {
        "title": "Node-RED e MQTT Expostos",
        "cvss": "9.8",
        "severity": "CRÍTICO",
        "impact": "Paralisação do chão de fábrica e sabotagem física das bombas.",
        "business": [
            "Interrupção operacional",
            "Perda financeira imediata",
            "Risco físico"
        ]
    },

    {
        "title": "SMB Signing Desabilitado",
        "cvss": "9.0",
        "severity": "ALTO",
        "impact": "Comprometimento total da rede via NTLM Relay.",
        "business": [
            "Movimentação lateral",
            "Perda de disponibilidade",
            "Escalada para domínio"
        ]
    }
]


# ==================================================
# AUTH
# ==================================================

USER = "admin"
PASS = "admin"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        if not session.get("logged"):
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated


# ==================================================
# LOGIN PAGE
# ==================================================

LOGIN_HTML = """

<!DOCTYPE html>
<html>

<head>

<title>CYMAG | Executive Portal</title>

<style>

*{
margin:0;
padding:0;
box-sizing:border-box;
font-family:Inter,Arial;
}

body{

background:
radial-gradient(circle at top,#15223f,#090c13);

height:100vh;

display:flex;

justify-content:center;

align-items:center;

color:white;

}

.card{

width:420px;

background:rgba(20,25,35,.92);

padding:45px;

border-radius:24px;

box-shadow:
0 0 60px rgba(0,0,0,.4);

border:1px solid rgba(255,255,255,.08);

}

.logo{

font-size:34px;

font-weight:800;

margin-bottom:6px;

}

.sub{

opacity:.7;

margin-bottom:35px;

}

input{

width:100%;

padding:16px;

margin-bottom:18px;

background:#111827;

border:none;

border-radius:12px;

color:white;

}

button{

width:100%;

padding:16px;

background:linear-gradient(
90deg,
#6d5dfc,
#4f46e5
);

border:none;

color:white;

font-weight:700;

border-radius:12px;

cursor:pointer;

transition:.2s;

}

button:hover{

transform:translateY(-2px);

}

.error{

color:#ff6b6b;

margin-top:12px;

}

.footer{

margin-top:24px;

font-size:12px;

opacity:.5;

text-align:center;

}

</style>

</head>

<body>

<div class="card">

<div class="logo">
CYMAG
</div>

<div class="sub">
Continuous Automated Red Teaming
</div>

<form method="POST">

<input
name="user"
placeholder="Usuário"
required
>

<input
type="password"
name="password"
placeholder="Senha"
required
>

<button>
Entrar no Dashboard
</button>

</form>

{% if error %}
<div class="error">
{{error}}
</div>
{% endif %}

<div class="footer">
Executive Risk Intelligence
</div>

</div>

</body>

</html>

"""


# ==================================================
# DASHBOARD
# ==================================================

DASHBOARD_HTML = """

<!DOCTYPE html>

<html>

<head>

<title>CYMAG Dashboard</title>

<style>

*{
margin:0;
padding:0;
box-sizing:border-box;
font-family:Inter;
}

body{

background:#070b12;

color:white;

padding:40px;

}

.header{

display:flex;

justify-content:space-between;

align-items:center;

margin-bottom:35px;

}

.brand{

font-size:36px;

font-weight:800;

}

.score{

background:
linear-gradient(
90deg,
#ff3b30,
#ff9500
);

padding:24px;

border-radius:22px;

width:350px;

}

.score h1{

font-size:58px;

}

.grid{

display:grid;

grid-template-columns:
repeat(
auto-fit,
minmax(350px,1fr)
);

gap:24px;

}

.card{

background:#111827;

padding:30px;

border-radius:22px;

border:1px solid rgba(255,255,255,.08);

}

.badge{

display:inline-block;

padding:8px 14px;

background:#991b1b;

border-radius:999px;

margin-bottom:16px;

}

.cvss{

font-size:42px;

font-weight:800;

margin-bottom:20px;

}

.subtitle{

opacity:.6;

margin-bottom:18px;

}

ul{

padding-left:18px;

}

li{

margin-bottom:10px;

opacity:.9;

}

.impact{

margin-top:18px;

padding:18px;

background:#1f2937;

border-radius:14px;

}

.logout{

color:#7aa2ff;

text-decoration:none;

}

</style>

</head>

<body>

<div class="header">

<div>

<div class="brand">
CYMAG
</div>

<div>
Executive Cyber Risk Dashboard
</div>

</div>

<div class="score">

<div>
GLOBAL RISK SCORE
</div>

<h1>
{{score}}/100
</h1>

<div>
{{level}}
</div>

</div>

</div>

<div style="margin-bottom:25px">
<a class="logout" href="/logout">
Encerrar sessão
</a>
</div>

<div class="grid">

{% for f in findings %}

<div class="card">

<div class="badge">
{{f.severity}}
</div>

<h2>
{{f.title}}
</h2>

<div class="subtitle">
Impacto Executivo
</div>

<div class="cvss">
CVSS {{f.cvss}}
</div>

<div class="impact">

{{f.impact}}

</div>

<br>

<strong>
Consequências para o Negócio
</strong>

<ul>

{% for i in f.business %}

<li>
{{i}}
</li>

{% endfor %}

</ul>

</div>

{% endfor %}

</div>

</body>

</html>

"""


# ==================================================
# ROUTES
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        if (
            request.form["user"] == USER
            and
            request.form["password"] == PASS
        ):

            session["logged"] = True

            return redirect("/")

        error = "Credenciais inválidas"

    return render_template_string(
        LOGIN_HTML,
        error=error
    )


@app.route("/")
@login_required
def dashboard():

    return render_template_string(
        DASHBOARD_HTML,
        score=RISK_SCORE,
        level=RISK_LEVEL,
        findings=FINDINGS
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==================================================
# START
# ==================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
