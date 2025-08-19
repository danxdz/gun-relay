# Gun Relay Server for Whisperz

Private Gun.js relay server for Whisperz P2P chat.

## Deploy to Render

1. Push this code to GitHub
2. Go to [render.com](https://render.com)
3. New > Web Service
4. Connect your GitHub repo
5. Deploy with free tier

## Connect from Whisperz

Add your relay URL:
```javascript
localStorage.setItem('GUN_CUSTOM_PEERS', 'https://your-relay.onrender.com/gun')
```

## Local Testing
```bash
npm install
npm start
```