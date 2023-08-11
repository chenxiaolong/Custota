/*
 * SPDX-FileCopyrightText: 2014-2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Based on DualBootPatcher code.
 */

#pragma once

#include <utility>

// Perform action once this goes out of scope, essentially acting as the
// "finally" part of a try-finally block (in eg. Java)
template <typename F>
class Finally
{
public:
    Finally() = delete;
    Finally(const Finally &) = delete;
    Finally & operator=(const Finally &) = delete;

    Finally(F f)
        : _f(std::move(f))
        , _dismissed(false)
    {
    }

    Finally(Finally &&other)
        : _f(std::move(other._f))
        , _dismissed(other._dismissed)
    {
        other.dismiss();
    }

    ~Finally() noexcept
    {
        // TODO: Uncomment if we're ever able to support exceptions
        //static_assert(noexcept(_f()), "Finally block must be noexcept");
        if (!_dismissed) {
            _f();
        }
    }

    Finally & operator=(Finally &&rhs)
    {
        _f = std::move(rhs._f);
        _dismissed = rhs._dismissed;
        rhs.dismiss();
        return *this;
    }

    void dismiss() noexcept
    {
        _dismissed = true;
    }

private:
    F _f;
    bool _dismissed;
};

template <typename F>
Finally<F> finally(F f)
{
    return { std::move(f) };
}
