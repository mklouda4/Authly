using System.Diagnostics;

namespace Authly.Services
{
    /// <summary>
    /// Background service for collecting system resource usage metrics
    /// </summary>
    public class ResourceMonitoringService(IServiceProvider serviceProvider, IApplicationLogger logger) : BackgroundService
    {
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(5); // Collect metrics every 5 minutes

        // Cache pro CPU měření
        private DateTime? _lastCpuTime;
        private TimeSpan? _lastProcessorTime;
        private double _lastCpuUsage = 0;
        private long? _lastLinuxCpuTicks;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            logger.LogInfo(nameof(ResourceMonitoringService), "Resource monitoring service started");

            // Zobrazíme info o prostředí při startu
            LogEnvironmentInfo();

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CollectResourceMetrics();
                    await Task.Delay(_interval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                    break;
                }
                catch (Exception ex)
                {
                    logger.LogError(nameof(ResourceMonitoringService), "Error collecting resource metrics", ex);
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); // Wait before retrying
                }
            }

            logger.LogInfo(nameof(ResourceMonitoringService), "Resource monitoring service stopped");
        }

        private async Task CollectResourceMetrics()
        {
            try
            {
                using var scope = serviceProvider.CreateScope();
                var metricsService = scope.ServiceProvider.GetRequiredService<IMetricsService>();
                var mqttService = scope.ServiceProvider.GetRequiredService<IMqttService>();

                // Get current process
                var currentProcess = Process.GetCurrentProcess();

                // Calculate CPU usage podle platformy
                var cpuUsage = GetCpuUsage();

                // Get memory usage - use actual physical memory
                var memoryUsageMB = currentProcess.WorkingSet64 / (1024.0 * 1024.0);

                // Get total physical memory (this is a more accurate approach)
                var totalMemoryMB = GetTotalPhysicalMemory() / (1024.0 * 1024.0);

                // Get thread count
                var activeThreads = currentProcess.Threads.Count;

                await metricsService.RecordResourceUsageMetricAsync(
                    cpuUsage,
                    memoryUsageMB,
                    totalMemoryMB,
                    activeThreads
                );

                // Record uptime metric
                var uptime = DateTime.UtcNow - currentProcess.StartTime.ToUniversalTime();
                await metricsService.RecordUptimeMetricAsync(
                    true,
                    null,
                    $"Service running for {uptime.TotalHours:F1} hours"
                );

                logger.LogDebug(nameof(ResourceMonitoringService),
                    $"Collected resource metrics: CPU {cpuUsage:F1}%, Memory {memoryUsageMB:F1}MB/{totalMemoryMB:F1}MB ({((memoryUsageMB / totalMemoryMB) * 100):F1}%), Threads {activeThreads}");

                await mqttService.PublishAsync(
                    "authly/resource/metrics",
                    new
                    {
                        CpuUsage = cpuUsage,
                        MemoryUsageMB = memoryUsageMB,
                        TotalMemoryMB = totalMemoryMB,
                        MemoryPercent = (memoryUsageMB / totalMemoryMB) * 100,
                        ActiveThreads = activeThreads,
                        UptimeHours = uptime.TotalHours
                    }
                );
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(ResourceMonitoringService), "Failed to collect resource metrics", ex);
            }
        }

        private double GetCpuUsage()
        {
            try
            {
                if (OperatingSystem.IsLinux())
                {
                    return GetLinuxCpuUsage();
                }
                else if (OperatingSystem.IsWindows())
                {
                    return GetWindowsCpuUsage();
                }
                else if (OperatingSystem.IsMacOS())
                {
                    return GetMacOSCpuUsage();
                }
                else
                {
                    return GetGenericCpuUsage();
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Could not calculate CPU usage accurately", ex);
                return _lastCpuUsage;
            }
        }

        private double GetLinuxCpuUsage()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var statPath = $"/proc/{currentProcess.Id}/stat";

                if (File.Exists(statPath))
                {
                    var statContent = File.ReadAllText(statPath);
                    var statFields = statContent.Split(' ');

                    if (statFields.Length >= 17)
                    {
                        if (long.TryParse(statFields[13], out var utime) &&
                            long.TryParse(statFields[14], out var stime))
                        {
                            var totalCpuTicks = utime + stime;
                            var currentTime = DateTime.UtcNow;

                            if (_lastCpuTime != null && _lastLinuxCpuTicks != null)
                            {
                                var timeDiff = (currentTime - _lastCpuTime.Value).TotalSeconds;
                                var cpuTicksDiff = totalCpuTicks - _lastLinuxCpuTicks.Value;

                                if (timeDiff > 0)
                                {
                                    var clockTicksPerSecond = GetLinuxClockTicks();
                                    var cpuUsage = (cpuTicksDiff / (clockTicksPerSecond * timeDiff)) * 100;

                                    cpuUsage = Math.Min(Math.Max(cpuUsage, 0), 100);

                                    _lastCpuTime = currentTime;
                                    _lastLinuxCpuTicks = totalCpuTicks;
                                    _lastCpuUsage = cpuUsage;

                                    logger.LogDebug(nameof(ResourceMonitoringService),
                                        $"Linux CPU calculation: {cpuTicksDiff} ticks in {timeDiff:F2}s = {cpuUsage:F2}%");

                                    return cpuUsage;
                                }
                            }

                            _lastCpuTime = currentTime;
                            _lastLinuxCpuTicks = totalCpuTicks;
                            return _lastCpuUsage;
                        }
                    }
                }

                logger.LogDebug(nameof(ResourceMonitoringService), "Linux /proc/stat not available, using generic method");
                return GetGenericCpuUsage();
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Linux CPU measurement failed", ex);
                return GetGenericCpuUsage();
            }
        }

        private long GetLinuxClockTicks()
        {
            try
            {
                return 100; // Standard Linux value
            }
            catch
            {
                return 100; // Default fallback
            }
        }

        private double GetWindowsCpuUsage()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var currentTime = DateTime.UtcNow;
                var currentProcessorTime = currentProcess.TotalProcessorTime;

                if (_lastCpuTime != null && _lastProcessorTime != null)
                {
                    var timeDiff = (currentTime - _lastCpuTime.Value).TotalMilliseconds;
                    var cpuDiff = (currentProcessorTime - _lastProcessorTime.Value).TotalMilliseconds;

                    if (timeDiff > 0)
                    {
                        var cpuUsage = (cpuDiff / (Environment.ProcessorCount * timeDiff)) * 100;
                        cpuUsage = Math.Min(Math.Max(cpuUsage, 0), 100);

                        _lastCpuTime = currentTime;
                        _lastProcessorTime = currentProcessorTime;
                        _lastCpuUsage = cpuUsage;

                        logger.LogDebug(nameof(ResourceMonitoringService),
                            $"Windows CPU calculation: {cpuDiff:F2}ms CPU in {timeDiff:F2}ms real = {cpuUsage:F2}%");

                        return cpuUsage;
                    }
                }

                _lastCpuTime = currentTime;
                _lastProcessorTime = currentProcessorTime;
                return _lastCpuUsage;
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Windows CPU measurement failed", ex);
                return GetGenericCpuUsage();
            }
        }

        private double GetMacOSCpuUsage()
        {
            try
            {
                return GetGenericCpuUsage();
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "macOS CPU measurement failed", ex);
                return GetGenericCpuUsage();
            }
        }

        private double GetGenericCpuUsage()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var currentTime = DateTime.UtcNow;
                var currentProcessorTime = currentProcess.TotalProcessorTime;

                if (_lastCpuTime != null && _lastProcessorTime != null)
                {
                    var timeDiff = (currentTime - _lastCpuTime.Value).TotalMilliseconds;
                    var cpuDiff = (currentProcessorTime - _lastProcessorTime.Value).TotalMilliseconds;

                    if (timeDiff > 0)
                    {
                        var cpuUsage = (cpuDiff / (Environment.ProcessorCount * timeDiff)) * 100;
                        cpuUsage = Math.Min(Math.Max(cpuUsage, 0), 100);

                        _lastCpuTime = currentTime;
                        _lastProcessorTime = currentProcessorTime;
                        _lastCpuUsage = cpuUsage;

                        return cpuUsage;
                    }
                }

                _lastCpuTime = currentTime;
                _lastProcessorTime = currentProcessorTime;
                return _lastCpuUsage;
            }
            catch
            {
                return _lastCpuUsage;
            }
        }

        private void LogEnvironmentInfo()
        {
            try
            {
                var isContainer = IsRunningInContainer();
                var containerLimit = GetContainerMemoryLimit();
                var totalMemory = GetTotalPhysicalMemory();

                logger.LogInfo(nameof(ResourceMonitoringService), "=== Environment Information ===");
                logger.LogInfo(nameof(ResourceMonitoringService), $"Operating System: {Environment.OSVersion}");
                logger.LogInfo(nameof(ResourceMonitoringService), $"Processor Count: {Environment.ProcessorCount}");
                logger.LogInfo(nameof(ResourceMonitoringService), $"Is 64-bit: {Environment.Is64BitOperatingSystem}");
                logger.LogInfo(nameof(ResourceMonitoringService), $"Running in Container: {isContainer}");

                if (OperatingSystem.IsWindows())
                    logger.LogInfo(nameof(ResourceMonitoringService), "Platform: Windows");
                else if (OperatingSystem.IsLinux())
                    logger.LogInfo(nameof(ResourceMonitoringService), "Platform: Linux");
                else if (OperatingSystem.IsMacOS())
                    logger.LogInfo(nameof(ResourceMonitoringService), "Platform: macOS");
                else
                    logger.LogInfo(nameof(ResourceMonitoringService), "Platform: Other/Unknown");

                logger.LogInfo(nameof(ResourceMonitoringService),
                    $"Total Memory: {totalMemory / (1024.0 * 1024.0):F0} MB");

                if (containerLimit > 0)
                {
                    logger.LogInfo(nameof(ResourceMonitoringService),
                        $"Container Memory Limit: {containerLimit / (1024.0 * 1024.0):F0} MB");
                }

                logger.LogInfo(nameof(ResourceMonitoringService), "===============================");
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Could not log environment info", ex);
            }
        }

        private long GetTotalPhysicalMemory()
        {
            try
            {
                // Try to detect container limits
                var containerMemory = GetContainerMemoryLimit();
                if (containerMemory > 0)
                {
                    return containerMemory;
                }

                if (OperatingSystem.IsWindows())
                {
                    return GetWindowsPhysicalMemory();
                }
                else if (OperatingSystem.IsLinux())
                {
                    return GetLinuxPhysicalMemory();
                }
                else if (OperatingSystem.IsMacOS())
                {
                    return GetMacOSPhysicalMemory();
                }
                else
                {
                    // Fallback: estimate based on GC memory pressure
                    return Environment.WorkingSet * 4; // Rough estimate
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Could not determine total physical memory, using fallback", ex);
                // Fallback to a reasonable default (8GB)
                return 8L * 1024 * 1024 * 1024;
            }
        }

        private long GetWindowsPhysicalMemory()
        {
            try
            {
                using var process = Process.GetCurrentProcess();

                try
                {
                    if (File.Exists("/proc/meminfo"))
                    {
                        return GetLinuxPhysicalMemory();
                    }

                    var workingSet = Environment.WorkingSet;

                    var multiplier = workingSet < 500 * 1024 * 1024 ? 128 : 64;
                    var estimatedTotal = workingSet * multiplier;

                    var minMemory = 4L * 1024 * 1024 * 1024;
                    var maxMemory = 256L * 1024 * 1024 * 1024;

                    var result = Math.Min(Math.Max(estimatedTotal, minMemory), maxMemory);

                    var commonSizes = new long[] {
                        4L * 1024 * 1024 * 1024,   // 4GB
                        8L * 1024 * 1024 * 1024,   // 8GB
                        16L * 1024 * 1024 * 1024,  // 16GB
                        32L * 1024 * 1024 * 1024,  // 32GB
                        64L * 1024 * 1024 * 1024,  // 64GB
                        128L * 1024 * 1024 * 1024, // 128GB
                        256L * 1024 * 1024 * 1024  // 256GB
                    };

                    foreach (var size in commonSizes)
                    {
                        if (result <= size * 1.2) // 20% tolerance
                            return size;
                    }

                    return result;
                }
                catch
                {
                    // Fallback 16GB
                    return 16L * 1024 * 1024 * 1024;
                }
            }
            catch
            {
                return 16L * 1024 * 1024 * 1024; // 16GB default
            }
        }

        private long GetContainerMemoryLimit()
        {
            try
            {
                // Docker/LXC container using cgroups for memory limits

                // Cgroups v2 (newer systems)
                var cgroupV2Paths = new[]
                {
                    "/sys/fs/cgroup/memory.max",
                    "/sys/fs/cgroup/unified/memory.max"
                };

                foreach (var path in cgroupV2Paths)
                {
                    if (File.Exists(path))
                    {
                        var content = File.ReadAllText(path).Trim();
                        if (content != "max" && long.TryParse(content, out var memoryMax))
                        {
                            logger.LogInfo(nameof(ResourceMonitoringService),
                                $"Detected cgroups v2 memory limit: {memoryMax / (1024.0 * 1024.0):F0} MB from {path}");
                            return memoryMax;
                        }
                    }
                }

                // Cgroups v1 (older systems)
                var cgroupV1Paths = new[]
                {
                    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                    "/sys/fs/cgroup/memory/docker/memory.limit_in_bytes",
                    "/sys/fs/cgroup/memory.limit_in_bytes"
                };

                foreach (var path in cgroupV1Paths)
                {
                    if (File.Exists(path))
                    {
                        var content = File.ReadAllText(path).Trim();
                        if (long.TryParse(content, out var memoryLimit))
                        {
                            // Check for "unlimited" (number is too high)
                            var unrestricted = 9223372036854775807L; // Long.MaxValue
                            var veryLarge = 1L << 50; // ~1PB - indicator of unlimited limit

                            if (memoryLimit < veryLarge && memoryLimit != unrestricted)
                            {
                                logger.LogInfo(nameof(ResourceMonitoringService),
                                    $"Detected cgroups v1 memory limit: {memoryLimit / (1024.0 * 1024.0):F0} MB from {path}");
                                return memoryLimit;
                            }
                            else
                            {
                                logger.LogDebug(nameof(ResourceMonitoringService),
                                    $"Found unlimited memory limit in {path}: {memoryLimit}");
                            }
                        }
                    }
                }

                // If cgroups is available, but no limit set, we assume it's running in a container without a memory limit
                if (IsRunningInContainer())
                {
                    logger.LogWarning(nameof(ResourceMonitoringService),
                        "Running in container but no memory limit detected - container may have unlimited memory");

                    var linuxMemory = GetLinuxPhysicalMemory();
                    logger.LogInfo(nameof(ResourceMonitoringService),
                        $"Using host memory as fallback in unlimited container: {linuxMemory / (1024.0 * 1024.0):F0} MB");
                    return linuxMemory;
                }

                return 0;
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Error detecting container memory limit", ex);
                return 0;
            }
        }

        private bool IsRunningInContainer()
        {
            try
            {
                // 1. Exists /.dockerenv file (Docker)
                if (File.Exists("/.dockerenv"))
                {
                    logger.LogDebug(nameof(ResourceMonitoringService), "Detected Docker container via /.dockerenv");
                    return true;
                }

                // 2. Check /proc/1/cgroup
                if (File.Exists("/proc/1/cgroup"))
                {
                    var cgroup = File.ReadAllText("/proc/1/cgroup");
                    if (cgroup.Contains("docker") || cgroup.Contains("lxc") || cgroup.Contains("kubepods"))
                    {
                        logger.LogDebug(nameof(ResourceMonitoringService),
                            $"Detected container via /proc/1/cgroup");
                        return true;
                    }
                }

                // 3. Check /proc/self/cgroup
                if (File.Exists("/proc/self/cgroup"))
                {
                    var cgroup = File.ReadAllText("/proc/self/cgroup");
                    if (cgroup.Contains("docker") || cgroup.Contains("lxc") || cgroup.Contains("kubepods"))
                    {
                        logger.LogDebug(nameof(ResourceMonitoringService),
                            "Detected container via /proc/self/cgroup");
                        return true;
                    }
                }

                // 4. Check hostname
                if (File.Exists("/proc/self/mountinfo"))
                {
                    var mountinfo = File.ReadAllText("/proc/self/mountinfo");
                    if (mountinfo.Contains("docker") || mountinfo.Contains("overlay"))
                    {
                        logger.LogDebug(nameof(ResourceMonitoringService),
                            "Detected container via /proc/self/mountinfo");
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                logger.LogDebug(nameof(ResourceMonitoringService), "Error detecting container environment", ex);
                return false;
            }
        }

        private long GetLinuxPhysicalMemory()
        {
            try
            {
                var memInfo = File.ReadAllText("/proc/meminfo");
                var lines = memInfo.Split('\n');

                foreach (var line in lines)
                {
                    if (line.StartsWith("MemTotal:"))
                    {
                        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && long.TryParse(parts[1], out var memKb))
                        {
                            var totalBytes = memKb * 1024;
                            logger.LogDebug(nameof(ResourceMonitoringService), $"Detected host physical memory: {totalBytes / (1024.0 * 1024.0):F0} MB");
                            return totalBytes;
                        }
                    }
                }

                throw new Exception("Could not parse /proc/meminfo");
            }
            catch
            {
                return 8L * 1024 * 1024 * 1024;
            }
        }

        private long GetMacOSPhysicalMemory()
        {
            try
            {
                // For macOS, we'd need to use system calls or process execution
                // For simplicity, use a reasonable estimate
                var workingSet = Environment.WorkingSet;
                return workingSet * 8; // Estimate
            }
            catch
            {
                return 8L * 1024 * 1024 * 1024; // 8GB default
            }
        }

        public override void Dispose()
        {
            logger.LogInfo(nameof(ResourceMonitoringService), "Disposing resource monitoring service");
            base.Dispose();
        }
    }
}