import requests, re, os, socket, json, base64, ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# --- НАСТРОЙКИ ---
WHITE_DOMAINS = ['yandex', 'vk.com', 'wb', 'gosuslugi', 'tinkoff', 'ok.ru', 'ozon', 'zoom.us', 'vkit.me', 'avito', 'mail', 'vk', 'ok', 'rzd', 'x5', 'alfabank', 'max', '2gis', 'mts', 'beeline', 't2', 'kinopoisk', 'sber', 'gov', 'duma', 'pochta', 'rbc', 'rutube', 'ivi', 'kion', 'magnit']
CHECK_TIMEOUT = 3
MAX_THREADS = 60

def safe_base64_decode(s):
    """Декодирует base64 с исправлением длины строки"""
    try:
        s = s.strip()
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
    except:
        return ""

def decode_vmess(vmess_str):
    try:
        data = vmess_str.replace("vmess://", "")
        return json.loads(safe_base64_decode(data))
    except: return None

def decode_ssr(ssr_str):
    """Извлекает host и port из ssr:// конфига"""
    try:
        data = ssr_str.replace("ssr://", "")
        decoded = safe_base64_decode(data)
        # Формат SSR: host:port:protocol:method:obfs:base64pass/?params
        parts = decoded.split(':')
        if len(parts) >= 2:
            return parts[0], parts[1]
    except: pass
    return None, None

def extract_info(key):
    """Извлекает адрес, порт, SNI и наличие TLS"""
    try:
        sni, use_tls = None, False
        
        if key.startswith("vmess://"):
            d = decode_vmess(key)
            if d:
                sni = d.get('sni') or d.get('host')
                use_tls = d.get('tls') == 'tls'
                return d.get('add'), d.get('port'), sni, use_tls
        
        if key.startswith("ssr://"):
            host, port = decode_ssr(key)
            return host, port, None, False

        parsed = urlparse(key)
        host, port = parsed.hostname, parsed.port
        
        if parsed.query:
            params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
            sni = params.get('sni') or params.get('host') or params.get('peer')
            if parsed.scheme in ['vless', 'trojan', 'hy2', 'hysteria2', 'hysteria', 'tuic']:
                use_tls = True
                
        return host, port, sni, use_tls
    except: return None, None, None, False

def smart_check(key):
    """Проверка живучести ключа"""
    host, port, sni, use_tls = extract_info(key)
    if not host or not port: return None
    
    # Мягкая проверка для UDP протоколов
    proto = key.split('://')[0]
    if proto in ['hy2', 'hysteria2', 'hysteria', 'tuic']:
        return {"key": key, "sni": sni}

    try:
        sock = socket.create_connection((host, int(port)), timeout=CHECK_TIMEOUT)
        if use_tls:
            context = ssl._create_unverified_context()
            try:
                with context.wrap_socket(sock, server_hostname=sni if sni else host) as ssock:
                    return {"key": key, "sni": sni}
            except:
                return None
            finally:
                sock.close()
        else:
            sock.close()
            return {"key": key, "sni": sni}
    except:
        return None

def main():
    if not os.path.exists('sources.txt'): 
        print("Ошибка: sources.txt не найден")
        return
        
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    raw_data = ""
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            content = r.text
            # Если весь файл зашифрован в base64 (обычно для SSR/V2ray подписок)
            if "://" not in content[:50]:
                content = safe_base64_decode(content)
            raw_data += content + "\n"
        except: pass

    # Поиск всех известных протоколов
    pattern = r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria2|hysteria|tuic)://[^\s"\'<>]+'
    all_found = re.findall(pattern, raw_data)
    unique_keys = list(set(all_found))

    print(f"Найдено уникальных: {len(unique_keys)}. Проверяю...")

    valid_results = []  # Список для валидных ключей
    seen_hashes = {}     # Словарь для отслеживания уникальных конфигураций

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(smart_check, unique_keys))
        for result in results:
            if result is not None:
                # Генерируем уникальный хэш для конфигурации
                config_hash = hash(result["key"])
                
                # Добавляем, только если такая конфигурация еще не встречалась
                if config_hash not in seen_hashes:
                    valid_results.append(result)
                    seen_hashes[config_hash] = result
                else:
                    print(f"Дубликат найден: {result['key']}")

    # Подготовка данных для сохранения
    output_data = {
        'all_keys.txt': [],
        'ss.txt': [],
        'ssr.txt': [],
        'vless.txt': [],
        'vmess.txt': [],
        'trojan.txt': [],
        'hy2.txt': [],
        'tuic.txt': [],
        'whitelist_optimized.txt': []
    }

    for res in valid_results:
        key = res['key'].strip()
        sni = str(res['sni']).lower() if res['sni'] else ""
        proto = key.split('://')[0]
        
        output_data['all_keys.txt'].append(key)
        
        # Распределение по файлам по типу протокола
        if proto == 'ss': output_data['ss.txt'].append(key)
        elif proto == 'ssr': output_data['ssr.txt'].append(key)
        elif proto == 'vless': output_data['vless.txt'].append(key)
        elif proto == 'vmess': output_data['vmess.txt'].append(key)
        elif proto == 'trojan': output_data['trojan.txt'].append(key)
        elif proto in ['hy2', 'hysteria2', 'hysteria']: output_data['hy2.txt'].append(key)
        elif proto == 'tuic': output_data['tuic.txt'].append(key)
        
        # Фильтрация белого списка доменов
        if any(d in sni or d in key.lower() for d in WHITE_DOMAINS):
            output_data['whitelist_optimized.txt'].append(key)

    # Записываем результаты
    if not os.path.exists('data'): os.makedirs('data')
    for filename, keys in output_data.items():
        with open(f'data/{filename}', 'w', encoding='utf-8') as f:
            if keys:
                f.write('\n'.join(keys) + '\n')

    print(f"Готово! Сохранено живых ключей: {len(valid_results)}")

if __name__ == "__main__":
    main()
