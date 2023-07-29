/*
 * Copyright (C) 2022-2023  Andrew Gunnerson
 *
 * This file is part of Custota, based on BCR code.
 *
 * Custota is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * Custota is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Custota.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.chiller3.custota.view

import android.content.Context
import android.util.AttributeSet
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder

/**
 * A thin shell over [Preference] that allows registering a long click listener.
 */
class LongClickablePreference : Preference {
    var onPreferenceLongClickListener: OnPreferenceLongClickListener? = null

    @Suppress("unused")
    constructor(context: Context) : super(context)

    @Suppress("unused")
    constructor(context: Context, attrs: AttributeSet?) : super(context, attrs)

    @Suppress("unused")
    constructor(context: Context, attrs: AttributeSet?, defStyleAttr: Int) :
            super(context, attrs, defStyleAttr)

    override fun onBindViewHolder(holder: PreferenceViewHolder) {
        super.onBindViewHolder(holder)

        val listener = onPreferenceLongClickListener
        if (listener == null) {
            holder.itemView.setOnLongClickListener(null)
            holder.itemView.isLongClickable = false
        } else {
            holder.itemView.setOnLongClickListener {
                listener.onPreferenceLongClick(this)
            }
        }
    }
}

interface OnPreferenceLongClickListener {
    fun onPreferenceLongClick(preference: Preference): Boolean
}
