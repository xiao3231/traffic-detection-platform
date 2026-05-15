/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type ICheckbox = {}

export default function Checkbox(props: ICheckbox) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
