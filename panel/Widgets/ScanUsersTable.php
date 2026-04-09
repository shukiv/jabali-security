<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Actions\BulkAction;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Illuminate\Support\Collection;
use Livewire\Component;

class ScanUsersTable extends Component implements HasActions, HasSchemas, HasTable
{
    use InteractsWithActions;
    use InteractsWithSchemas;
    use InteractsWithTable;

    protected function client(): JabaliSecurityClient
    {
        return JabaliSecurityClient::getInstance();
    }

    protected function scanPath(string $username): array
    {
        $path = '/home/' . $username;
        $result = $this->client()->post('/scan', ['path' => $path]);

        $threats = [];
        if ($result && ! empty($result['results'])) {
            foreach ($result['results'] as $r) {
                $threats[] = [
                    'path' => $r['path'] ?? '',
                    'score' => $r['score'] ?? 0,
                    'action' => $r['action'] ?? '',
                    'findings' => $r['findings'] ?? [],
                ];
            }
        }

        return [
            'success' => $result !== null,
            'files' => $result['files_scanned'] ?? 0,
            'threats_count' => $result['threats_found'] ?? $result['score'] ?? 0,
            'threats' => $threats,
        ];
    }

    protected function formatThreatBody(array $threats): string
    {
        if (empty($threats)) {
            return __('No threats found');
        }

        $lines = [];
        foreach (array_slice($threats, 0, 10) as $t) {
            $path = basename($t['path'] ?? '');
            $score = $t['score'] ?? 0;
            $findings = collect($t['findings'] ?? [])
                ->pluck('rule')
                ->implode(', ');
            $lines[] = "• {$path} (score: {$score}) — {$findings}";
        }

        if (count($threats) > 10) {
            $lines[] = __('... and :more more', ['more' => count($threats) - 10]);
        }

        return implode("\n", $lines);
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(function () {
                try {
                    // Get hosting users from the panel database
                    $panelUsers = \App\Models\User::query()
                        ->select('id', 'name', 'username')
                        ->whereNotNull('username')
                        ->where('username', '!=', '')
                        ->get();

                    // Get incident stats from security daemon
                    $incidentUsers = $this->client()->get('/users') ?? [];
                    $incidentMap = [];
                    foreach ($incidentUsers as $u) {
                        $incidentMap[$u['username'] ?? ''] = $u;
                    }

                    $records = [];
                    foreach ($panelUsers as $user) {
                        $username = $user->username;
                        $incidents = $incidentMap[$username] ?? [];
                        $records[] = [
                            'username' => $username,
                            'incident_count' => $incidents['incident_count'] ?? 0,
                            'max_score' => $incidents['max_score'] ?? 0,
                            'quarantine_count' => $incidents['quarantine_count'] ?? 0,
                            'path' => '/home/' . $username,
                        ];
                    }

                    // Add users with incidents but not in the panel DB
                    $panelUsernames = $panelUsers->pluck('username')->all();
                    foreach ($incidentUsers as $u) {
                        $username = $u['username'] ?? '';
                        if (! $username || in_array($username, $panelUsernames, true)) {
                            continue;
                        }
                        $records[] = [
                            'username' => $username,
                            'incident_count' => $u['incident_count'] ?? 0,
                            'max_score' => $u['max_score'] ?? 0,
                            'quarantine_count' => $u['quarantine_count'] ?? 0,
                            'path' => '/home/' . $username,
                        ];
                    }

                    return $records;
                } catch (\Exception) {
                    return [];
                }
            })
            ->columns([
                TextColumn::make('username')
                    ->label(__('User'))
                    ->weight('bold')
                    ->searchable(),
                TextColumn::make('path')
                    ->label(__('Path'))
                    ->fontFamily('mono')
                    ->size('sm')
                    ->color('gray'),
                TextColumn::make('incident_count')
                    ->label(__('Incidents'))
                    ->badge()
                    ->color(fn ($state): string => (int) $state > 0 ? 'danger' : 'gray'),
                TextColumn::make('max_score')
                    ->label(__('Max Score'))
                    ->badge()
                    ->color(fn ($state): string => match (true) {
                        (int) $state >= 70 => 'danger',
                        (int) $state >= 40 => 'warning',
                        default => 'gray',
                    }),
                TextColumn::make('quarantine_count')
                    ->label(__('Quarantined'))
                    ->badge()
                    ->color(fn ($state): string => (int) $state > 0 ? 'warning' : 'gray'),
            ])
            ->recordActions([
                Action::make('scan')
                    ->label(__('Scan'))
                    ->icon('heroicon-o-magnifying-glass')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $username = $record['username'] ?? '';

                        Notification::make()
                            ->title(__('Scanning :user...', ['user' => $username]))
                            ->info()
                            ->send();

                        $r = $this->scanPath($username);

                        $notification = Notification::make()
                            ->title($r['success']
                                ? __(':user — :files files, :threats threats', ['user' => $username, 'files' => $r['files'], 'threats' => $r['threats_count']])
                                : __('Scan failed for :user', ['user' => $username]))
                            ->{$r['success'] ? ($r['threats_count'] > 0 ? 'warning' : 'success') : 'danger'}();

                        if ($r['threats_count'] > 0) {
                            $notification->body($this->formatThreatBody($r['threats']))
                                ->persistent();
                        } else {
                            $notification->duration(10000);
                        }

                        $notification->send();
                    }),
            ])
            ->headerActions([
                Action::make('scanAll')
                    ->label(__('Scan All Users'))
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->modalDescription(__('Each user will be scanned individually. You will see progress notifications for each user.'))
                    ->action(function (): void {
                        $panelUsers = \App\Models\User::query()
                            ->whereNotNull('username')
                            ->where('username', '!=', '')
                            ->pluck('username')
                            ->all();
                        $totalFiles = 0;
                        $totalThreats = 0;
                        $allThreats = [];
                        $scanned = 0;
                        $count = count($panelUsers);

                        foreach ($panelUsers as $username) {
                            if (! $username) {
                                continue;
                            }

                            $scanned++;
                            Notification::make('scan-progress')
                                ->title(__('Scanning :n/:total — :user', ['n' => $scanned, 'total' => $count, 'user' => $username]))
                                ->info()
                                ->send();

                            $r = $this->scanPath($username);
                            if ($r['success']) {
                                $totalFiles += $r['files'];
                                $totalThreats += $r['threats_count'];
                                $allThreats = array_merge($allThreats, $r['threats']);
                            }
                        }

                        $notification = Notification::make()
                            ->title(__('Scan complete — :users users', ['users' => $scanned]))
                            ->body(
                                __(':files files scanned, :threats threats found', ['files' => $totalFiles, 'threats' => $totalThreats])
                                . ($totalThreats > 0 ? "\n\n" . $this->formatThreatBody($allThreats) : '')
                            )
                            ->{$totalThreats > 0 ? 'warning' : 'success'}();

                        if ($totalThreats > 0) {
                            $notification->persistent();
                        } else {
                            $notification->duration(15000);
                        }

                        $notification->send();
                    }),
            ])
            ->bulkActions([
                BulkAction::make('scanSelected')
                    ->label(__('Scan Selected'))
                    ->icon('heroicon-o-magnifying-glass')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->deselectRecordsAfterCompletion()
                    ->action(function (Collection $records): void {
                        $totalFiles = 0;
                        $totalThreats = 0;
                        $allThreats = [];
                        $scanned = 0;
                        $count = $records->count();

                        foreach ($records as $record) {
                            $username = $record['username'] ?? '';
                            if (! $username) {
                                continue;
                            }

                            $scanned++;
                            Notification::make('scan-progress')
                                ->title(__('Scanning :n/:total — :user', ['n' => $scanned, 'total' => $count, 'user' => $username]))
                                ->info()
                                ->send();

                            $r = $this->scanPath($username);
                            if ($r['success']) {
                                $totalFiles += $r['files'];
                                $totalThreats += $r['threats_count'];
                                $allThreats = array_merge($allThreats, $r['threats']);
                            }
                        }

                        $notification = Notification::make()
                            ->title(__('Scan complete — :users users', ['users' => $scanned]))
                            ->body(
                                __(':files files scanned, :threats threats found', ['files' => $totalFiles, 'threats' => $totalThreats])
                                . ($totalThreats > 0 ? "\n\n" . $this->formatThreatBody($allThreats) : '')
                            )
                            ->{$totalThreats > 0 ? 'warning' : 'success'}();

                        if ($totalThreats > 0) {
                            $notification->persistent();
                        } else {
                            $notification->duration(15000);
                        }

                        $notification->send();
                    }),
            ])
            ->emptyStateHeading(__('No users found'))
            ->emptyStateDescription(__('No hosting users detected on this server'))
            ->emptyStateIcon('heroicon-o-users')
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
