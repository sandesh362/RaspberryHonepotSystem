import argparse
import json
from .app.config import Settings

def main():
    parser=argparse.ArgumentParser(description='SentinelPi local control plane')
    parser.add_argument('command',choices=['serve','credentials','verify'],default='serve',nargs='?')
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--open-browser',action='store_true')
    args=parser.parse_args()
    settings=Settings()
    if args.command=='serve':
        import uvicorn
        from .app.api import create_app
        app=create_app(settings)
        credentials=json.loads((settings.data_dir/'local-credentials.json').read_text())
        print('\nSentinelPi / local-only software lab')
        print('Workspace: http://127.0.0.1:'+str(args.port))
        print('Username: '+credentials['username'])
        print('Password: '+credentials['password'])
        print('Private credentials file: '+str(settings.data_dir/'local-credentials.json'))
        print('Raspberry Pi integration: Phase 2. Replay is labeled separately.\n',flush=True)
        if args.open_browser:
            import threading,time,webbrowser
            from urllib.request import urlopen
            def open_when_ready():
                url='http://127.0.0.1:'+str(args.port)
                for _ in range(120):
                    try:
                        with urlopen(url+'/api/health',timeout=.5) as response:
                            if response.status==200:
                                webbrowser.open(url); return
                    except OSError: pass
                    time.sleep(.25)
            threading.Thread(target=open_when_ready,daemon=True).start()
        uvicorn.run(app,host='127.0.0.1',port=args.port,log_level='info')
    elif args.command=='credentials':
        path=settings.data_dir/'local-credentials.json'
        if not path.exists(): raise SystemExit('Start the server once to create credentials.')
        data=json.loads(path.read_text()); print('Username: '+data['username']); print('Password: '+data['password'])
    else:
        from .app.database import Database
        print(json.dumps(Database(settings.data_dir/'sentinel.db').verify_chain(),indent=2))

if __name__=='__main__': main()
