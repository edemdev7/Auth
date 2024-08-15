<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Laravel\Socialite\Facades\Socialite;
use App\Models\User;
use App\Models\OauthProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;


class OAuthController extends Controller
{
    public function redirectToProvider($provider)
    {
        return Socialite::driver($provider)->redirect();
    }

    public function handleProviderCallback($provider)
    {
        $socialUser = Socialite::driver($provider)->user();

        // Debug: vérifier le contenu de $socialUser
        if (is_null($socialUser)) {
            return redirect('/login')->with('error', 'Failed to retrieve user information from provider.');
        }

        // Vérifier si l'ID du fournisseur est disponible
        if (is_null($socialUser->getId())) {
            return redirect('/login')->with('error', 'Provider did not return a valid ID.');
        }

        $oauthProvider = OauthProvider::where('provider', $provider)
            ->where('provider_id', $socialUser->getId())
            ->first();

        if ($oauthProvider) {
            $user = $oauthProvider->user;
        } else {
            // Vérifier si l'email est disponible
            if (is_null($socialUser->getEmail())) {
                return redirect('/login')->with('error', 'Provider did not return a valid email.');
            }

            $user = User::where('email', $socialUser->getEmail())->first();

            if (!$user) {
                $user = User::create([
                    'name' => $socialUser->getName(),
                    'email' => $socialUser->getEmail(),
                    'password' => bcrypt(Str::random(16)), // Mot de passe aléatoire au cas ou
                    'auth_method' => 'oauth2'
                ]);

                OauthProvider::create([
                    'user_id' => $user->id,
                    'provider' => $provider,
                    'provider_id' => $socialUser->getId(),
                ]);
            } else {
                // Mise à jour de la méthode d'authentification si nécessaire
                if ($user->auth_method != 'both') {
                    $user->auth_method = 'both';
                    $user->save();
                }
            }
        }

        Auth::login($user);
        return redirect('/dashboard');
    }
}
