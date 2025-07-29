using System.Diagnostics;

namespace Authly.Services
{
    /// <summary>
    /// Background service for collecting system resource usage metrics
    /// </summary>
    public class ResourceMonitoringService(IServiceProvider serviceProvider, IApplicationLogger logger) : BackgroundService
    {
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(5); // Collect metrics every 5 minutes

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            logger.LogInfo(nameof(ResourceMonitoringService), "Resource monitoring service started");

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

                // Calculate CPU usage (simplified approach)
                var cpuUsage = await GetCpuUsageAsync();

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

        private async Task<double> GetCpuUsageAsync()
        {
            try
            {
                // More accurate CPU usage calculation using PerformanceCounter-like approach
                var currentProcess = Process.GetCurrentProcess();
                var startTime = DateTime.UtcNow;
                var startCpuUsage = currentProcess.TotalProcessorTime;

                // Wait a bit to get a meaningful measurement
                await Task.Delay(500);

                var endTime = DateTime.UtcNow;
                var endCpuUsage = currentProcess.TotalProcessorTime;

                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;

                if (totalMsPassed <= 0) return 0;

                var cpuUsageTotal = (cpuUsedMs / (Environment.ProcessorCount * totalMsPassed)) * 100;

                return Math.Min(Math.Max(cpuUsageTotal, 0), 100);
            }
            catch (Exception ex)
            {
                logger.LogWarning(nameof(ResourceMonitoringService), "Could not calculate CPU usage accurately", ex);
                return 0; // Return 0 if we can't calculate CPU usage
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

                // If cgroups is availaible, but no limit set, we assume it's running in a container without a memory limit
                if (IsRunningInContainer())
                {
                    logger.LogWarning(nameof(ResourceMonitoringService), "Running in container but no memory limit detected");

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
                // Několik způsobů, jak detekovat kontejner:

                // 1. Exists /.dockerenv file (Docker)
                if (File.Exists("/.dockerenv"))
                {
                    return true;
                }

                // 2. Check /proc/1/cgroup
                if (File.Exists("/proc/1/cgroup"))
                {
                    var cgroup = File.ReadAllText("/proc/1/cgroup");
                    if (cgroup.Contains("docker") || cgroup.Contains("lxc") || cgroup.Contains("kubepods"))
                    {
                        return true;
                    }
                }

                // 3. Check /proc/self/cgroup
                if (File.Exists("/proc/self/cgroup"))
                {
                    var cgroup = File.ReadAllText("/proc/self/cgroup");
                    if (cgroup.Contains("docker") || cgroup.Contains("lxc") || cgroup.Contains("kubepods"))
                    {
                        return true;
                    }
                }

                // 4. Check hostname
                if (File.Exists("/proc/self/mountinfo"))
                {
                    var mountinfo = File.ReadAllText("/proc/self/mountinfo");
                    if (mountinfo.Contains("docker") || mountinfo.Contains("overlay"))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
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
                            logger.LogInfo(nameof(ResourceMonitoringService), $"Detected host physical memory: {totalBytes / (1024.0 * 1024.0):F0} MB");
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