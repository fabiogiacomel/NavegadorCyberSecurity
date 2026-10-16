# =====================================================================
# Menu Interativo em PowerShell para o Navegador CyberSecurity
# =====================================================================

$Host.UI.RawUI.WindowTitle = "CyberSecurity Browser - Central de Comando"

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host "   CYBERSECURITY BROWSER - VIBE CODING & OWASP TOP 10 AUDITOR          " -ForegroundColor Green
    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host "   Bancada de Auditoria Defensiva para Sistemas Desenvolvidos com IA   " -ForegroundColor Gray
    Write-Host ""
}

function Check-Python {
    try {
        $pyVer = python --version 2>&1
        Write-Host " [OK] Ambiente: $pyVer detectado" -ForegroundColor DarkGreen
    } catch {
        Write-Host " [AVISO] Python nao encontrado no PATH do sistema!" -ForegroundColor Red
    }
}

function Show-Menu {
    Show-Banner
    Check-Python
    Write-Host ""
    Write-Host " Escolha uma opcao:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Iniciar Navegador (Pagina Inicial de Boas-Vindas)" -ForegroundColor White
    Write-Host "  [2] Iniciar Navegador em URL ou Porta Especifica (ex: 3000, 5173)" -ForegroundColor White
    Write-Host "  [3] Iniciar Servidor de Teste Vulneravel (demo_vulnerable_app)" -ForegroundColor White
    Write-Host "  [4] Modo Demonstracao Completo (Servidor Teste + Navegador)" -ForegroundColor Cyan
    Write-Host "  [5] Executar Bateria de Testes Automatizados (Unit & E2E)" -ForegroundColor Magenta
    Write-Host "  [6] Instalar / Verificar Dependencias (requirements.txt)" -ForegroundColor DarkYellow
    Write-Host "  [7] Abrir Documentacao do Projeto (README.md)" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  [0] Sair" -ForegroundColor DarkGray
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host " Digite o numero da opcao desejada"

    switch ($choice) {
        "1" {
            Write-Host "`n [i] Inicializando Navegador CyberSecurity..." -ForegroundColor Cyan
            python main.py
        }

        "2" {
            Write-Host ""
            Write-Host " Exemplos rapidos:" -ForegroundColor Gray
            Write-Host " - Digite apenas a porta (ex: 3000, 5173, 5000, 8000)" -ForegroundColor Gray
            Write-Host " - Ou a URL completa (ex: https://meusistema.com.br)" -ForegroundColor Gray
            $target = Read-Host "`n Informe a URL ou Porta"
            if ($target -ne "") {
                Write-Host " [i] Abrindo navegador em: $target..." -ForegroundColor Cyan
                python main.py $target
            }
        }

        "3" {
            Write-Host "`n [i] Iniciando Servidor Vulneravel de Teste na porta 5050..." -ForegroundColor Yellow
            Write-Host " [!] Pressione Ctrl+C para encerrar o servidor a qualquer momento.`n" -ForegroundColor Gray
            python demo_vulnerable_app.py 5050
        }

        "4" {
            Write-Host "`n [i] Configurando Modo Demonstracao Completo..." -ForegroundColor Cyan
            Write-Host " [1/2] Iniciando servidor de teste em segundo plano (porta 5050)..." -ForegroundColor Yellow
            
            # Inicia o servidor em processo separado
            $serverProcess = Start-Process python -ArgumentList "demo_vulnerable_app.py 5050" -PassThru -WindowStyle Minimized
            Start-Sleep -Seconds 1

            Write-Host " [2/2] Abrindo Navegador CyberSecurity em http://localhost:5050..." -ForegroundColor Green
            python main.py http://localhost:5050

            # Ao fechar o navegador, encerra o servidor de teste
            if ($serverProcess -and -not $serverProcess.HasExited) {
                Write-Host "`n [i] Finalizando servidor de teste em segundo plano..." -ForegroundColor Gray
                Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
            }
            Write-Host " [OK] Sessao concluida." -ForegroundColor Green
            Start-Sleep -Seconds 1
        }

        "5" {
            Write-Host "`n [i] Executando bateria de testes do sistema..." -ForegroundColor Magenta
            python -m unittest discover tests -v
            Write-Host "`n Pressione Enter para retornar ao menu..." -ForegroundColor Gray
            Read-Host
        }

        "6" {
            Write-Host "`n [i] Verificando e instalando pacotes necessarios..." -ForegroundColor Yellow
            pip install -r requirements.txt
            Write-Host "`n [OK] Verificacao concluida!" -ForegroundColor Green
            Write-Host " Pressione Enter para retornar ao menu..." -ForegroundColor Gray
            Read-Host
        }

        "7" {
            Write-Host "`n [i] Abrindo documentacao..." -ForegroundColor Blue
            if (Get-Command "code" -ErrorAction SilentlyContinue) {
                code README.md
            } else {
                notepad README.md
            }
        }

        "0" {
            Write-Host "`n Encerrando. Ate logo!`n" -ForegroundColor Green
            exit
        }

        default {
            Write-Host "`n [!] Opcao invalida! Escolha um numero entre 0 e 7." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }

} while ($choice -ne "0")
