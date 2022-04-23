import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { Navbar } from './components/layout/Navbar';
import { Landing } from './components/layout/Landing';
import { Register } from './components/auth/Register';
import { Login } from './components/auth/Login';

function App() {
	return (
		<Router>
			<Navbar />
			<section className='container'>
				<Routes>
					<Route path='/' element={<Landing />} />
					<Route path='/register' element={<Register />} />
					<Route path='/login' element={<Login />} />
				</Routes>
			</section>
		</Router>
	);
}

export default App;
