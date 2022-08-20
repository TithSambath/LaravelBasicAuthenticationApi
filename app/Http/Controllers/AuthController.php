<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    function signUp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->passes()) {

            $user = User::create([
                'username' => $request->username,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            $token = $user->createToken($request->device_name)->plainTextToken;

            return response()->json([
                'status' => 201,
                'message' => 'User created successfully',
                'data' => ['token' => $token],
            ], 200);
        } else {
            return response()->json([
                'status' => 400,
                'message' => 'Bad request',
                'data' => $validator->errors(),
            ], 200);
        }
    }

    function signIn(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 400,
                'message' => 'Bad request',
                'data' => $validator->errors(),
            ], 200);
        }

        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return response()->json([
                'status' => 404,
                'message' => 'User not found',
                'data' => null
            ], 200);
        }
        if (!Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => 401,
                'message' => 'Password does not match',
                'data' => null
            ], 200);
        }
        $token = $user->createToken($request->device_name)->plainTextToken;
        return response()->json([
            'status' => '200',
            'message' => 'User logged in successfully',
            'data' => ['token' => $token],
        ], 200);
    }
}
