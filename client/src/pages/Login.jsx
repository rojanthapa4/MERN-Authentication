import React, { useState } from "react";
import { assets } from "../assets/assets";

const Login = () => {
  const [state, setState] = useState("Sign up");

  return (
    <div
      className="flex items-center justify-center min-h-screen px-6 
    sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400"
    >
      <img
        src={assets.logo}
        alt=""
        className="absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer"
      />
      <div className="bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm">
        <h2 className="text-3xl font-semibold text-white text-center mb-3">
          {state === "Sign up" ? "Create account" : "Login!"}
        </h2>
        <p className="text-center text-sm mb-6">
          {state === "Sign up"
            ? "Create you account"
            : "Login to your account!"}
        </p>
        <form>
          <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
            <img src={assets.person_icon} alt="" />
            <input
              className="bg-transparent outline-none"
              type="text"
              placeholder="Full Name"
              required
            />
          </div>
          <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
            <img src={assets.mail_icon} alt="" />
            <input
              className="bg-transparent outline-none"
              type="email"
              placeholder="Email Id"
              required
            />
          </div>
          <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
            <img src={assets.lock_icon} alt="" />
            <input
              className="bg-transparent outline-none"
              type="password"
              placeholder="Password"
              required
            />
          </div>
          <p className="mb-4 text-indigo-500 cursor-pointer">
            Forgot Password?
          </p>
          <button className="w-full py-2.5 rounded-full bg-gradient-to-br from-indigo-500 to-indigo-900 text-white font-medium">
            {state === "Sign up" ? "Sign up" : "Login"}
          </button>
        </form>
        <p>
          Already have an account?
          <span>Login here</span>
        </p>
      </div>
    </div>
  );
};

export default Login;
