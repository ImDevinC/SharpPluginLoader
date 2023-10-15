﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Threading.Tasks;

namespace SharpPluginLoader.Core
{
    internal class PluginManager
    {
        public static PluginManager Instance { get; } = new();
        public static string DefaultPluginDirectory => "nativePC/plugins/CSharp";

        private struct PluginContext
        {
            public PluginLoadContext Context { get; init; }
            public Assembly Assembly { get; init; }
            public IPlugin Plugin { get; init; }
            public PluginData Data { get; init; }
        }

        private readonly Dictionary<string, PluginContext> _contexts = new();

        public void LoadPlugins(string directory)
        {
            foreach (var pluginPath in Directory.GetFiles(directory, "*.dll", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(Path.GetDirectoryName(pluginPath)) == "Loader")
                    continue;

                LoadPlugin(pluginPath);
            }
        }

        public void LoadPlugin(string pluginPath)
        {
            if (!File.Exists(pluginPath))
            {
                Log.Warn($"Plugin {pluginPath} does not exist");
                return;
            }

            Log.Debug($"assembly context: {AssemblyLoadContext.GetLoadContext(Assembly.GetExecutingAssembly())!.Name}");

            var pluginName = Path.GetFileNameWithoutExtension(pluginPath);

            lock (_contexts)
            {
                if (_contexts.ContainsKey(pluginName))
                    return;
            }
            
            var context = new PluginLoadContext(pluginPath);

            var assembly = context.LoadFromAssemblyName(new AssemblyName(pluginName));
            var pluginType = assembly.GetTypes().FirstOrDefault(type => typeof(IPlugin).IsAssignableFrom(type));

            if (pluginType == null)
            {
                Log.Warn($"Plugin {pluginPath} does not implement IPlugin");
                return;
            }

            if (Activator.CreateInstance(pluginType) is not IPlugin plugin)
            {
                Log.Warn($"Failed to create instance of {pluginType.FullName}");
                return;
            }

            var pluginData = plugin.OnLoad();

            lock (_contexts)
            {
                _contexts.Add(pluginName, new PluginContext
                {
                    Context = context,
                    Assembly = assembly,
                    Plugin = plugin,
                    Data = pluginData
                });
            }
        }

        public void InvokeOnUpdate(float deltaTime)
        {
            lock (_contexts)
            {
                foreach (var context in _contexts.Values.Where(context => context.Data.OnUpdate))
                {
                    context.Plugin.OnUpdate(deltaTime);
                }
            }
        }

        public void ReloadPlugins(string directory)
        {
            foreach (var pluginPath in Directory.GetFiles(directory, "*.dll", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(Path.GetDirectoryName(pluginPath)) == "Loader")
                    continue;

                UnloadPlugin(pluginPath);
            }

            LoadPlugins(directory);
        }

        public void ReloadPlugin(string pluginPath)
        {
            UnloadPlugin(pluginPath);
            LoadPlugin(pluginPath);
        }

        public void UnloadAllPlugins()
        {
            lock (_contexts)
            {
                foreach (var context in _contexts.Values)
                    context.Context.Unload();

                _contexts.Clear();
            }
        }

        private void UnloadPlugin(string pluginPath)
        {
            var pluginName = Path.GetFileNameWithoutExtension(pluginPath);
            lock (_contexts)
            {
                if (!_contexts.TryGetValue(pluginName, out var context))
                    return;

                context.Context.Unload();
                _contexts.Remove(pluginName);
            }
        }
    }
}
