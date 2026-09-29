//-----------------------------------------------------------------------------
// Filename: InlineList.cs
//
// Description: A small list that keeps its first items inline, so building one
// allocates nothing until it outgrows that. Replaces the Small package's
// SmallList, which depended on TypeNum (a 2021 prerelease that pulled in
// NETStandard.Library 1.6.1).
//
// History:
// Sep 2026     iSpyConnect     Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace SIPSorcery.Sys
{
    /// <summary>
    /// A list that stores its first <see cref="InlineCapacity"/> items inline and the rest in a
    /// <see cref="List{T}"/>. It is a mutable struct: add to it through a local, a field or a ref, never
    /// through a copy - a copy is a separate list (that shares any overflow items).
    /// </summary>
    public struct InlineList<T> : IEnumerable<T>
    {
        public const int InlineCapacity = 8;

        [InlineArray(8)]
        private struct InlineBuffer
        {
            private T _element0;
        }

        private InlineBuffer _inline;
        private List<T> _overflow;
        private int _count;

        public readonly int Count => _count;

        public readonly T this[int index]
        {
            get
            {
                if ((uint)index >= (uint)_count)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                return index < InlineCapacity ? _inline[index] : _overflow[index - InlineCapacity];
            }
        }

        public void Add(T item)
        {
            if (_count < InlineCapacity)
            {
                _inline[_count] = item;
            }
            else
            {
                (_overflow ??= new List<T>()).Add(item);
            }

            _count++;
        }

        public readonly Enumerator GetEnumerator() => new Enumerator(this);

        IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public struct Enumerator : IEnumerator<T>
        {
            private readonly InlineList<T> _list;
            private int _index;

            internal Enumerator(InlineList<T> list)
            {
                _list = list;
                _index = -1;
            }

            public readonly T Current => _list[_index];

            object IEnumerator.Current => Current;

            public bool MoveNext() => ++_index < _list.Count;

            public void Reset() => _index = -1;

            public readonly void Dispose()
            { }
        }
    }
}
