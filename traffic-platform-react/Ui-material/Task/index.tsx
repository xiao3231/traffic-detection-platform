/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type ITask = {}

export default function Task(props: ITask) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
