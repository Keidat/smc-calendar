"""일관된 SQLite 백업을 생성합니다. 실행: python backup.py"""
import datetime as dt
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3

root=Path(__file__).resolve().parent
source=root/'school.db'
if not source.exists():
    raise SystemExit('school.db가 없습니다. 먼저 서버를 한 번 실행하세요.')
target=root/'backups'/dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
target.mkdir(parents=True)
with closing(sqlite3.connect(source)) as db:
    with closing(sqlite3.connect(target/'school.db')) as backup:
        db.backup(backup)
if (root/'config.json').exists():shutil.copy2(root/'config.json',target/'config.json')
print(f'백업 완료: {target}')
print('SMTP 비밀번호가 담긴 .env.local은 이 백업에 포함되지 않습니다.')
