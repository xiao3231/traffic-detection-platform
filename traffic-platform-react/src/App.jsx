import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Home from './pages/Home'
import Detection from './pages/Detection'
import History from './pages/History'
import ProtocolAnalysis from './pages/ProtocolAnalysis'
import AdminUsers from './pages/AdminUsers'
import Profile from './pages/Profile'
import './App.css'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<Home />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/history" element={<History />} />
        <Route path="/analysis" element={<ProtocolAnalysis />} />
        <Route path="/admin/users" element={<AdminUsers />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
