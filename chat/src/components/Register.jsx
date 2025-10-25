import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaUser, FaLock, FaEnvelope } from 'react-icons/fa'; // Icons for better UX

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        // confirmPassword: '',
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();

    // 1. Handle input changes and update state
    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
        // Clear error when user starts typing
        if (error) setError(''); 
    };

    // 2. Handle form submission
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        // Basic validation
        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match.');
            setLoading(false);
            return;
        }

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData),
            });

            if (response.ok) {
                navigate('/login'); // Navigate to login after successful registration
            } else {
                const data = await response.json();
                setError(data.message || 'Registration failed.');
            }
        } catch (err) {
            setError('Network error. Please try again.', err);
        }

        // Simulate a successful registration delay for demonstration
        setTimeout(() => {
            console.log("Registration Attempt:", formData);
            setLoading(false);
            alert("Registration successful! Redirecting to login.");
            navigate('/login'); 
        }, 1500); 
    };

    return (
        // Main container: full screen, centered content
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            
            {/* Registration Card */}
            <div className="w-full max-w-md bg-white rounded-xl shadow-2xl p-8 space-y-8 transform transition-all duration-300 hover:shadow-3xl">
                
                <h2 className="text-3xl font-extrabold text-center text-gray-900">
                    Create Your Account
                </h2>
                
                {/* Error Display */}
                {error && (
                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
                        <span className="block sm:inline">{error}</span>
                    </div>
                )}

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    
                    {/* Username Field */}
                    <div className="relative">
                        <FaUser className="absolute top-1/2 left-3 transform -translate-y-1/2 text-gray-400" />
                        <input
                            id="username"
                            name="username"
                            type="text"
                            required
                            value={formData.username}
                            onChange={handleChange}
                            placeholder="Username"
                            className="appearance-none rounded-md relative block w-full pl-10 pr-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                        />
                    </div>

                    {/* Email Field */}
                    <div className="relative">
                        <FaEnvelope className="absolute top-1/2 left-3 transform -translate-y-1/2 text-gray-400" />
                        <input
                            id="email"
                            name="email"
                            type="email"
                            required
                            value={formData.email}
                            onChange={handleChange}
                            placeholder="Email address"
                            className="appearance-none rounded-md relative block w-full pl-10 pr-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                        />
                    </div>

                    {/* Password Field */}
                    <div className="relative">
                        <FaLock className="absolute top-1/2 left-3 transform -translate-y-1/2 text-gray-400" />
                        <input
                            id="password"
                            name="password"
                            type="password"
                            required
                            value={formData.password}
                            onChange={handleChange}
                            placeholder="Password"
                            className="appearance-none rounded-md relative block w-full pl-10 pr-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                        />
                    </div>

                    {/* Confirm Password Field */}
                    {/* <div className="relative">
                        <FaLock className="absolute top-1/2 left-3 transform -translate-y-1/2 text-gray-400" />
                        <input
                            id="confirmPassword"
                            name="confirmPassword"
                            type="password"
                            required
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            placeholder="Confirm Password"
                            className="appearance-none rounded-md relative block w-full pl-10 pr-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                        />
                    </div> */}

                    {/* Submit Button */}
                    <button
                        type="submit"
                        disabled={loading}
                        className={`
                            group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white 
                            ${loading ? 'bg-indigo-400 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'}
                            transition duration-150 ease-in-out
                        `}
                    >
                        {loading ? 'Registering...' : 'Register'}
                    </button>
                </form>

                {/* Link to Login */}
                <div className="text-sm text-center">
                    <span className="font-medium text-gray-600">
                        Already have an account?{' '}
                        <button
                            onClick={() => navigate('/login')}
                            className="text-indigo-600 hover:text-indigo-500 font-semibold transition-colors duration-150"
                        >
                            Log in
                        </button>
                    </span>
                </div>
            </div>
        </div>
    );
};

export default Register;