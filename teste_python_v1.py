def main():

    print(BANNER)

    print("\n════════════════════════════════════")
    print("CYMAG — Continuous Automated Red Teaming")
    print("════════════════════════════════════\n")

    while True:

        target = input(
            "Alvo (IP ou CIDR): "
        ).strip()

        if target:
            break

        print("\n[ERRO] Informe um alvo válido.\n")

    print()

    api_key = input(
        "Groq API Key (Enter para ignorar IA): "
    ).strip()

    print("\n──────────────────────────────")
    print("Iniciando varredura...")
    print("──────────────────────────────\n")

    scanner = CYMAGScanner(
        target,
        debug=False
    )

    findings = scanner.run()

    print(f"\n[SCAN] {len(findings)} achado(s).\n")

    ai_data = {}

    if api_key:

        print(
            "[IA] Traduzindo impacto executivo...\n"
        )

        findings_sorted = sorted(
            findings,
            key=lambda x:
            SEVERITY_ORDER.get(
                x.severity,
                0
            ),
            reverse=True
        )

        ai_data = ai_analyze(
            findings_sorted,
            api_key
        )

        for i, f in enumerate(
            findings_sorted
        ):

            fd = (
                ai_data
                .get(
                    "findings",
                    {}
                )
                .get(
                    str(i),
                    {}
                )
            )

            f.ai_analysis = (
                fd.get(
                    "analysis",
                    ""
                )
            )

            f.ai_recommendation = (
                fd.get(
                    "recommendation",
                    ""
                )
            )

    print(
        "\n[HTML] Construindo dashboard..."
    )

    html = gen_html(
        findings,
        target,
        scanner.scan_time,
        ai_data
    )

    full = os.path.abspath(
        html
    )

    print("\nDashboard criado:")
    print(full)

    print(
        "\nAbrindo navegador..."
    )

    import threading
    import webbrowser
    import time

    def open_dashboard():

        time.sleep(1)

        webbrowser.open(
            "file://" + full
        )

    threading.Thread(
        target=open_dashboard,
        daemon=True
    ).start()

    print(
        "\n════════════════════════════════════"
    )

    print(
        "Dashboard aberto."
    )

    print(
        "Feche com CTRL+C."
    )

    print(
        "════════════════════════════════════"
    )

    try:

        while True:

            time.sleep(60)

    except KeyboardInterrupt:

        print("\nEncerrando...")


if __name__ == "__main__":

    main()
