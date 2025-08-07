from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from ..database.models import SecurityEvent, Agent
from ..database.database import get_db, engine
from ..detection.rules import ThreatDetector
from ..utils.config import load_config


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.agent_connections: Dict[str, WebSocket] = {}

    async def connect_client(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def connect_agent(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        self.agent_connections[agent_id] = websocket

    def disconnect_client(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def disconnect_agent(self, agent_id: str):
        if agent_id in self.agent_connections:
            del self.agent_connections[agent_id]

    async def broadcast_to_clients(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                self.active_connections.remove(connection)

    async def send_to_agent(self, agent_id: str, message: str):
        if agent_id in self.agent_connections:
            try:
                await self.agent_connections[agent_id].send_text(message)
                return True
            except:
                del self.agent_connections[agent_id]
                return False
        return False


app = FastAPI(title="Security Monitor Dashboard", version="1.0.0")
config = load_config()
manager = ConnectionManager()
threat_detector = ThreatDetector()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security_monitor.dashboard")


@app.get("/")
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Monitor Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://unpkg.com/react@18/umd/react.development.js"></script>
        <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
        <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
            .events-container { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .events-header { background: #34495e; color: white; padding: 15px; border-radius: 8px 8px 0 0; }
            .event-item { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: between; align-items: center; }
            .event-item:last-child { border-bottom: none; }
            .severity-critical { border-left: 4px solid #e74c3c; }
            .severity-warning { border-left: 4px solid #f39c12; }
            .severity-info { border-left: 4px solid #3498db; }
            .timestamp { color: #7f8c8d; font-size: 0.9em; }
            .event-type { font-weight: 500; }
            .agent-status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
            .agent-online { background: #2ecc71; }
            .agent-offline { background: #e74c3c; }
            .filters { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
            .filter-button { padding: 8px 16px; border: none; border-radius: 4px; background: #ecf0f1; cursor: pointer; }
            .filter-button.active { background: #3498db; color: white; }
        </style>
    </head>
    <body>
        <div id="root"></div>
        
        <script type="text/babel">
            const { useState, useEffect } = React;
            
            function Dashboard() {
                const [events, setEvents] = useState([]);
                const [stats, setStats] = useState({
                    totalEvents: 0,
                    criticalEvents: 0,
                    warningEvents: 0,
                    activeAgents: 0
                });
                const [filter, setFilter] = useState('all');
                const [ws, setWs] = useState(null);
                
                useEffect(() => {
                    // Initialize WebSocket connection
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
                    const websocket = new WebSocket(wsUrl);
                    
                    websocket.onopen = () => {
                        console.log('Connected to WebSocket');
                        setWs(websocket);
                    };
                    
                    websocket.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        
                        if (data.type === 'security_events') {
                            setEvents(prevEvents => [...data.events, ...prevEvents].slice(0, 100));
                        } else if (data.type === 'stats_update') {
                            setStats(data.stats);
                        }
                    };
                    
                    websocket.onclose = () => {
                        console.log('WebSocket connection closed');
                        // Attempt to reconnect after 5 seconds
                        setTimeout(() => {
                            window.location.reload();
                        }, 5000);
                    };
                    
                    // Load initial data
                    fetch('/api/events?limit=50')
                        .then(response => response.json())
                        .then(data => setEvents(data));
                        
                    fetch('/api/stats')
                        .then(response => response.json())
                        .then(data => setStats(data));
                    
                    return () => {
                        if (websocket) {
                            websocket.close();
                        }
                    };
                }, []);
                
                const filteredEvents = events.filter(event => {
                    if (filter === 'all') return true;
                    return event.severity === filter;
                });
                
                return (
                    <div className="container">
                        <div className="header">
                            <h1>Security Monitor Dashboard</h1>
                            <p>Real-time security monitoring and threat detection</p>
                        </div>
                        
                        <div className="stats-grid">
                            <div className="stat-card">
                                <div className="stat-value">{stats.totalEvents}</div>
                                <div>Total Events</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-value" style={{color: '#e74c3c'}}>{stats.criticalEvents}</div>
                                <div>Critical Events</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-value" style={{color: '#f39c12'}}>{stats.warningEvents}</div>
                                <div>Warning Events</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-value" style={{color: '#2ecc71'}}>{stats.activeAgents}</div>
                                <div>Active Agents</div>
                            </div>
                        </div>
                        
                        <div className="filters">
                            <button 
                                className={`filter-button ${filter === 'all' ? 'active' : ''}`}
                                onClick={() => setFilter('all')}
                            >
                                All Events
                            </button>
                            <button 
                                className={`filter-button ${filter === 'critical' ? 'active' : ''}`}
                                onClick={() => setFilter('critical')}
                            >
                                Critical
                            </button>
                            <button 
                                className={`filter-button ${filter === 'warning' ? 'active' : ''}`}
                                onClick={() => setFilter('warning')}
                            >
                                Warning
                            </button>
                            <button 
                                className={`filter-button ${filter === 'info' ? 'active' : ''}`}
                                onClick={() => setFilter('info')}
                            >
                                Info
                            </button>
                        </div>
                        
                        <div className="events-container">
                            <div className="events-header">
                                <h2>Recent Security Events ({filteredEvents.length})</h2>
                            </div>
                            <div>
                                {filteredEvents.length === 0 ? (
                                    <div style={{padding: '20px', textAlign: 'center', color: '#7f8c8d'}}>
                                        No events found
                                    </div>
                                ) : (
                                    filteredEvents.map((event, index) => (
                                        <div key={index} className={`event-item severity-${event.severity}`}>
                                            <div style={{flex: 1}}>
                                                <div className="event-type">{event.type}</div>
                                                <div style={{color: '#7f8c8d', fontSize: '0.9em', marginTop: '4px'}}>
                                                    Source: {event.source}
                                                </div>
                                                {event.data && typeof event.data === 'object' && (
                                                    <div style={{fontSize: '0.8em', color: '#95a5a6', marginTop: '4px'}}>
                                                        {JSON.stringify(event.data).substring(0, 100)}...
                                                    </div>
                                                )}
                                            </div>
                                            <div>
                                                <div className="timestamp">
                                                    {new Date(event.timestamp).toLocaleString()}
                                                </div>
                                                <div style={{textAlign: 'right', marginTop: '4px'}}>
                                                    <span style={{
                                                        padding: '2px 8px', 
                                                        borderRadius: '12px', 
                                                        fontSize: '0.8em',
                                                        backgroundColor: event.severity === 'critical' ? '#e74c3c' : 
                                                                         event.severity === 'warning' ? '#f39c12' : '#3498db',
                                                        color: 'white'
                                                    }}>
                                                        {event.severity}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>
                );
            }
            
            ReactDOM.render(<Dashboard />, document.getElementById('root'));
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/events")
async def get_events(
    limit: int = 100,
    severity: str = None,
    event_type: str = None,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    
    return [{
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "type": event.event_type,
        "source": event.source,
        "severity": event.severity,
        "data": json.loads(event.data) if event.data else {}
    } for event in events]


@app.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)):
    # Calculate stats for the last 24 hours
    last_24h = datetime.now() - timedelta(hours=24)
    
    total_events = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= last_24h
    ).count()
    
    critical_events = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= last_24h,
        SecurityEvent.severity == "critical"
    ).count()
    
    warning_events = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= last_24h,
        SecurityEvent.severity == "warning"
    ).count()
    
    # Count active agents (agents that sent data in the last 5 minutes)
    last_5min = datetime.now() - timedelta(minutes=5)
    active_agents = db.query(Agent).filter(
        Agent.last_seen >= last_5min
    ).count()
    
    return {
        "totalEvents": total_events,
        "criticalEvents": critical_events,
        "warningEvents": warning_events,
        "activeAgents": active_agents
    }


@app.get("/api/agents")
async def get_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    
    return [{
        "id": agent.id,
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "status": "online" if agent.last_seen and (datetime.now() - agent.last_seen).seconds < 300 else "offline"
    } for agent in agents]


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect_client(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_client(websocket)


@app.websocket("/ws/agent")
async def websocket_agent(websocket: WebSocket):
    agent_id = None
    try:
        await websocket.accept()
        
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get('type') == 'security_events':
                agent_id = message.get('agent_id', 'unknown')
                
                # Update or create agent record
                db = next(get_db())
                agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
                if not agent:
                    agent = Agent(
                        agent_id=agent_id,
                        hostname=message.get('hostname', 'unknown'),
                        ip_address=message.get('ip_address', 'unknown')
                    )
                    db.add(agent)
                
                agent.last_seen = datetime.now()
                db.commit()
                
                # Process events
                events = message.get('events', [])
                db_events = []
                
                for event_data in events:
                    # Run threat detection
                    threat_result = threat_detector.analyze_event(event_data)
                    if threat_result:
                        event_data['severity'] = threat_result.severity
                        event_data['threat_type'] = threat_result.threat_type
                    
                    # Store in database
                    db_event = SecurityEvent(
                        timestamp=datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00')),
                        event_type=event_data['type'],
                        source=event_data['source'],
                        severity=event_data['severity'],
                        data=json.dumps(event_data['data']),
                        agent_id=agent.id
                    )
                    db.add(db_event)
                    db_events.append(event_data)
                
                db.commit()
                db.close()
                
                # Broadcast to dashboard clients
                if db_events:
                    await manager.broadcast_to_clients(json.dumps({
                        'type': 'security_events',
                        'events': db_events
                    }))
                    
                    logger.info(f"Processed {len(db_events)} events from agent {agent_id}")
    
    except WebSocketDisconnect:
        if agent_id:
            manager.disconnect_agent(agent_id)


if __name__ == "__main__":
    import uvicorn
    
    # Create database tables
    from ..database.models import Base
    Base.metadata.create_all(bind=engine)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)