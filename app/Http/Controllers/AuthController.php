<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use illuminate\support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request) {
        $user = User::create([
            "name" => $request->input("name"),
            "email" => $request->input("email"),
            "password" => Hash::make($request->input("password")),
        ]);

        return $user;
    }

    public function user() {
        return Auth::user();
    }

    public function login(Request $request) {
        if (!Auth::attempt($request->only("email", "password"))) {
            return response([
                "message" => "invalid User",
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();

        $token = $request->user()->createToken("token")->plainTextToken;

        $cookie = cookie("jwt", $token, 60); // 1 jam

        return response([
            "message" => "success",
            "token" => $token,

        ])->withCookie($cookie);
    }

    public function logout() {

        $cookie = Cookie::forget("jwt");

       return response([
           "message" => "logout success",
       ])->withCookie($cookie);
    }
}
