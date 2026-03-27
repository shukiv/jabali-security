<?php

declare(strict_types=1);

namespace App\JabaliSecurity;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class JabaliSecurityClient
{
    protected string $baseUrl = 'http://127.0.0.1:9876/api/v1';

    protected ?string $apiKey = null;

    public function __construct()
    {
        $this->apiKey = $this->loadApiKey();
    }

    public function get(string $path, array $query = []): ?array
    {
        try {
            $response = Http::withHeaders($this->headers())
                ->timeout(10)
                ->get($this->baseUrl.$path, $query);

            if ($response->successful()) {
                $data = $response->json();

                return $data['data'] ?? $data;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('JabaliSecurity API error: '.$e->getMessage());

            return null;
        }
    }

    public function post(string $path, array $data = []): ?array
    {
        try {
            $response = Http::withHeaders($this->headers())
                ->timeout(10)
                ->post($this->baseUrl.$path, $data);

            if ($response->successful()) {
                $result = $response->json();

                return $result['data'] ?? $result;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('JabaliSecurity API error: '.$e->getMessage());

            return null;
        }
    }

    public function patch(string $path, array $data = []): ?array
    {
        try {
            $response = Http::withHeaders($this->headers())
                ->timeout(10)
                ->patch($this->baseUrl.$path, $data);

            if ($response->successful()) {
                $result = $response->json();

                return $result['data'] ?? $result;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('JabaliSecurity API error: '.$e->getMessage());

            return null;
        }
    }

    public function delete(string $path): ?array
    {
        try {
            $response = Http::withHeaders($this->headers())
                ->timeout(10)
                ->delete($this->baseUrl.$path);

            if ($response->successful()) {
                $result = $response->json();

                return $result['data'] ?? $result;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('JabaliSecurity API error: '.$e->getMessage());

            return null;
        }
    }

    public function isAvailable(): bool
    {
        try {
            $response = Http::withHeaders($this->headers())
                ->timeout(3)
                ->get($this->baseUrl.'/health');

            return $response->successful();
        } catch (\Exception) {
            return false;
        }
    }

    protected function headers(): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($this->apiKey) {
            $headers['X-API-Key'] = $this->apiKey;
        }

        return $headers;
    }

    protected function loadApiKey(): ?string
    {
        $configFile = '/etc/jabali-security/jabali-security.conf';
        if (! file_exists($configFile)) {
            return null;
        }

        $content = file_get_contents($configFile);
        if ($content === false) {
            return null;
        }

        if (preg_match('/^API_KEY="([^"]*)"$/m', $content, $matches)) {
            return $matches[1] !== '' ? $matches[1] : null;
        }

        return null;
    }
}
