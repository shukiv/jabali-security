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

        return [
            'success' => $result !== null,
            'files' => $result['files_scanned'] ?? 0,
            'threats' => $result['threats_found'] ?? $result['score'] ?? 0,
        ];
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(function () {
                // Get system users from /home/
                $sshUsers = $this->client()->get('/ssh/users') ?? [];
                // Get incident stats
                $incidentUsers = $this->client()->get('/users') ?? [];
                $incidentMap = [];
                foreach ($incidentUsers as $u) {
                    $incidentMap[$u['username'] ?? ''] = $u;
                }

                $records = [];
                foreach ($sshUsers as $user) {
                    $username = $user['username'] ?? '';
                    if (! $username) {
                        continue;
                    }
                    $incidents = $incidentMap[$username] ?? [];
                    $records[] = [
                        'username' => $username,
                        'incident_count' => $incidents['incident_count'] ?? 0,
                        'max_score' => $incidents['max_score'] ?? 0,
                        'quarantine_count' => $incidents['quarantine_count'] ?? 0,
                        'path' => '/home/' . $username,
                    ];
                }

                // Add users with incidents but not in ssh/users
                foreach ($incidentUsers as $u) {
                    $username = $u['username'] ?? '';
                    if (! $username) {
                        continue;
                    }
                    $found = false;
                    foreach ($records as $r) {
                        if ($r['username'] === $username) {
                            $found = true;
                            break;
                        }
                    }
                    if (! $found) {
                        $records[] = [
                            'username' => $username,
                            'incident_count' => $u['incident_count'] ?? 0,
                            'max_score' => $u['max_score'] ?? 0,
                            'quarantine_count' => $u['quarantine_count'] ?? 0,
                            'path' => '/home/' . $username,
                        ];
                    }
                }

                return $records;
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

                        Notification::make()
                            ->title($r['success']
                                ? __(':user — :files files, :threats threats', ['user' => $username, 'files' => $r['files'], 'threats' => $r['threats']])
                                : __('Scan failed for :user', ['user' => $username]))
                            ->{$r['success'] ? ($r['threats'] > 0 ? 'warning' : 'success') : 'danger'}()
                            ->duration(10000)
                            ->send();
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
                        $sshUsers = $this->client()->get('/ssh/users') ?? [];
                        $totalFiles = 0;
                        $totalThreats = 0;
                        $scanned = 0;
                        $count = count($sshUsers);

                        foreach ($sshUsers as $user) {
                            $username = $user['username'] ?? '';
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
                                $totalThreats += $r['threats'];
                            }
                        }

                        Notification::make()
                            ->title(__('Scan complete — :users users', ['users' => $scanned]))
                            ->body(__(':files files scanned, :threats threats found', ['files' => $totalFiles, 'threats' => $totalThreats]))
                            ->{$totalThreats > 0 ? 'warning' : 'success'}()
                            ->duration(15000)
                            ->send();
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
                                $totalThreats += $r['threats'];
                            }
                        }

                        Notification::make()
                            ->title(__('Scan complete — :users users', ['users' => $scanned]))
                            ->body(__(':files files scanned, :threats threats found', ['files' => $totalFiles, 'threats' => $totalThreats]))
                            ->{$totalThreats > 0 ? 'warning' : 'success'}()
                            ->duration(15000)
                            ->send();
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
