﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SharpPluginLoader.Core
{
    /// <summary>
    /// This class represents a Monster Hunter World: Iceborne data type info.
    /// </summary>
    public class MtDti : MtObject
    {
        private unsafe nint NewInstance() => ((delegate* unmanaged[Fastcall]<nint, nint>)GetVirtualFunction(1))(Instance);
        private unsafe nint CtorInstance(nint obj) => ((delegate* unmanaged[Fastcall]<nint, nint, nint>)GetVirtualFunction(2))(Instance, obj);

        /// <summary>
        /// Constructs a new instance of <see cref="MtDti"/> with the specified native pointer.
        /// </summary>
        /// <param name="instance"></param>
        public MtDti(nint instance) : base(instance) { }

        /// <summary>
        /// Constructs a new instance of <see cref="MtDti"/> with nullptr as the native pointer.
        /// </summary>
        public MtDti() { }

        /// <summary>
        /// Gets the name of the class.
        /// </summary>
        public string Name => Marshal.PtrToStringAnsi(Get<nint>(0x8))!;

        /// <summary>
        /// Gets the next class in the list.
        /// </summary>
        public MtDti? Next => GetObject<MtDti>(0x10);

        /// <summary>
        /// Gets the first child class of this class.
        /// </summary>
        public MtDti? Child => GetObject<MtDti>(0x18);

        /// <summary>
        /// Gets all classes that inherit directly from this class.
        /// </summary>
        public MtDti[] Children
        {
            get
            {
                var children = new List<MtDti>();
                for (var child = Child; child != null; child = child.Next)
                    children.Add(child);
                return children.ToArray();
            }
        }

        /// <summary>
        /// Gets all classes that inherit from this class (directly or indirectly).
        /// </summary>
        public MtDti[] AllChildren
        {
            get
            {
                var children = new List<MtDti>();
                for (var child = Child; child != null; child = child.Next)
                {
                    children.Add(child);
                    children.AddRange(child.AllChildren);
                }
                return children.ToArray();
            }
        }

        /// <summary>
        /// Gets the parent class of this class.
        /// </summary>
        public MtDti? Parent => GetObject<MtDti>(0x20);

        /// <summary>
        /// Gets the linked class of this class. This property is used by the game to form a hash table of classes.
        /// </summary>
        public MtDti? Link => GetObject<MtDti>(0x28);

        /// <summary>
        /// Gets the size in bytes of the class.
        /// </summary>
        public uint Size => (Get<uint>(0x30) & 0x7FFFFF) << 2;

        /// <summary>
        /// Gets the index of the allocator used by this class.
        /// </summary>
        public uint AllocatorIndex => (Get<uint>(0x30) >> 23) & 0x3F;

        /// <summary>
        /// Gets the attributes of the class.
        /// </summary>
        public uint Attributes => Get<uint>(0x30) >> 29;

        /// <summary>
        /// Gets the id of the class.
        /// </summary>
        public uint Id => Get<uint>(0x34);

        /// <summary>
        /// Checks if this class inherits from the class with the specified CRC.
        /// </summary>
        /// <param name="id">The CRC hash of the class to check</param>
        /// <returns>True if the class inherits from the specified class</returns>
        public bool InheritsFrom(uint id)
        {
            for (var dti = this; dti != null; dti = dti.Parent)
            {
                if (dti.Id == id)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if this class inherits from the class with the specified name.
        /// </summary>
        /// <param name="name">The name of the class to check</param>
        /// <returns>True if the class inherits from the specified class</returns>
        public bool InheritsFrom(string name)
        {
            return InheritsFrom(MakeId(name));
        }

        /// <summary>
        /// Checks if this class inherits from the specified class.
        /// </summary>
        /// <param name="dti">The class to check for</param>
        /// <returns>True if the class inherits from the specified class</returns>
        public bool InheritsFrom(MtDti dti)
        {
            return InheritsFrom(dti.Id);
        }

        /// <summary>
        /// Creates and instantiates a new instance of the of the type represented by this class.
        /// </summary>
        /// <typeparam name="T">The type of the object</typeparam>
        /// <returns>The created object</returns>
        public T CreateInstance<T>() where T : MtObject, new()
        {
            return new T
            {
                Instance = NewInstance()
            };
        }

        /// <summary>
        /// Instantiates the specified object with the type represented by this class.
        /// </summary>
        /// <typeparam name="T">The type of the object</typeparam>
        /// <param name="obj">The object to instantiate</param>
        /// <returns>The object if the instantiation was successfull or null</returns>
        public T? Instantiate<T>(T obj) where T : MtObject
        {
            return CtorInstance(obj.Instance) != 0 ? obj : null;
        }

        /// <summary>
        /// Computes the dti id of a class from its name.
        /// </summary>
        /// <param name="name">The name of the class</param>
        /// <returns>The computed dti id of the class</returns>
        public static uint MakeId(string name)
        {
            return Utility.Crc32(name) & 0x7FFFFFFF;
        }

        /// <summary>
        /// Finds a DTI by its id.
        /// </summary>
        /// <param name="id">The id of the class</param>
        /// <returns>The DTI or null if no DTI was found</returns>
        public static MtDti? Find(uint id)
        {
            var dti = Utility.FindDti(id);
            return dti == 0 ? null : new MtDti(dti);
        }

        /// <summary>
        /// Finds a DTI by its name.
        /// </summary>
        /// <param name="name">The fully qualified name of the class</param>
        /// <returns>The DTI or null if no DTI was found</returns>
        public static MtDti? Find(string name)
        {
            return Find(MakeId(name));
        }
    }
}
